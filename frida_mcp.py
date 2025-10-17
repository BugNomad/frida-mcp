"""
Frida MCP Server - Minimal Android Hook Service using FastMCP

This module provides a Model Context Protocol (MCP) server that enables AI models
to perform Android dynamic analysis using Frida. It handles device connection,
process management, and script injection.
"""

import time
import asyncio
import json
import os
import logging
from typing import Optional, Dict, Any, Deque, Callable, Tuple
from collections import defaultdict, deque
from device_manager import DeviceManager
import frida
from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Global state management
device: Optional[frida.core.Device] = None
session: Optional[frida.core.Session] = None

# Global message buffer (store raw log lines)
messages_buffer: Deque[str] = deque(maxlen=5000)

# Keep strong references to loaded scripts to prevent GC unloading
active_scripts: list[Any] = []


def _frida_log(text: str) -> None:
    """
    Append a log message to the global buffer.

    Args:
        text: The log message to append
    """
    try:
        messages_buffer.append(f"[frida] {text}")
        logger.debug(f"Frida log: {text}")
    except Exception as e:
        logger.error(f"Failed to append to message buffer: {e}")


def _bind_session_events(sess: frida.core.Session) -> None:
    """
    Bind session events to capture detach reasons.

    Args:
        sess: The Frida session to bind events to
    """
    try:
        def on_detached(reason: str) -> None:
            _frida_log(f"session detached: {reason}")

        sess.on('detached', on_detached)
        logger.info("Session events bound successfully")
    except Exception as e:
        logger.error(f"Failed to bind session events: {e}")
        _frida_log(f"bind detached failed: {e}")

# Initialize FastMCP
app = FastMCP("frida-mcp")


def _load_config() -> Dict[str, Any]:
    """
    Load configuration from config.json file.

    Searches for config.json in:
    1. Same directory as this script
    2. Current working directory

    Returns:
        Dictionary with configuration values, using defaults if file not found
    """
    default_config: Dict[str, Any] = {
        "server_path": None,
        "server_name": None,
        "server_port": 27042,
        "device_id": None,
        "adb_path": "adb",
    }

    # Try relative to this file first, then CWD
    candidates = [
        os.path.join(os.path.dirname(__file__), "config.json"),
        os.path.join(os.getcwd(), "config.json"),
    ]

    for cfg_path in candidates:
        try:
            if os.path.isfile(cfg_path):
                with open(cfg_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    default_config.update(loaded)
                    logger.info(f"Configuration loaded from {cfg_path}")
                    return default_config
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in {cfg_path}: {e}")
        except Exception as e:
            logger.warning(f"Failed to load config from {cfg_path}: {e}")

    logger.info("Using default configuration")
    return default_config


CONFIG = _load_config()



def wrap_script_for_mcp(user_script: str) -> str:
    """
    Wrap user script to redirect console.log and handle object serialization.

    This function:
    1. Redirects console.log to send() to avoid stdout pollution
    2. Attempts to serialize objects using Gson (if available)
    3. Falls back to toString() and class name inspection

    Args:
        user_script: The JavaScript script provided by the user

    Returns:
        The wrapped script with console.log redirection and object serialization
    """
    return f"""
    // Smart object-to-string function (prioritizes Gson)
    function safeStringify(obj) {{
        if (obj === null) return 'null';
        if (obj === undefined) return 'undefined';

        // Primitive types - return directly
        if (typeof obj === 'string') return obj;
        if (typeof obj === 'number' || typeof obj === 'boolean') return String(obj);

        // Object types - attempt conversion
        try {{
            // Try Gson first (if app has Gson library)
            var Gson = Java.use('com.google.gson.Gson');
            var gson = Gson.$new();
            return gson.toJson(obj);
        }} catch (gsonError) {{
            try {{
                // Fallback to toString()
                return obj.toString();
            }} catch (toStringError) {{
                try {{
                    // Last resort: get class name
                    return '[' + (obj.$className || 'Unknown') + ' Object]';
                }} catch (classError) {{
                    return '[Unparseable Object]';
                }}
            }}
        }}
    }}

    // Redirect console.log to send() to avoid stdout pollution
    console.log = function() {{
        var message = Array.prototype.slice.call(arguments).map(function(arg) {{
            return safeStringify(arg);
        }}).join(' ');
        send({{'type': 'log', 'message': message}});
    }};

    // User script
    {user_script}
    """


def create_message_collector(
    external_buffer: Optional[Deque[str]] = None
) -> Tuple[Callable[[Dict[str, Any], Any], None], list[str]]:
    """
    Create a message handler that collects Frida script output.

    Args:
        external_buffer: Optional external buffer to append messages to

    Returns:
        Tuple of (message_handler function, messages list)
    """
    messages: list[str] = []

    def on_message(message: Dict[str, Any], data: Any) -> None:
        """Handle Frida script messages."""
        try:
            # Handle different message types
            if message.get('type') == 'send':
                payload = message.get('payload', {})
                if isinstance(payload, dict) and payload.get('type') == 'log':
                    # This is a console.log message redirected by our wrapper
                    text = payload.get('message', str(payload))
                else:
                    # Other send() messages
                    text = str(payload)
            elif message.get('type') == 'error':
                # Script errors
                stack = message.get('stack', message.get('description', str(message)))
                text = f"[Error] {stack}"
            else:
                # Other message types
                if 'payload' in message:
                    text = str(message['payload'])
                else:
                    text = str(message)

            messages.append(text)
            if external_buffer is not None:
                external_buffer.append(text)
            logger.debug(f"Message collected: {text[:100]}")
        except Exception as e:
            logger.error(f"Error processing message: {e}")

    return on_message, messages


async def _load_script_with_global_buffer(
    session: frida.core.Session,
    initial_script: Optional[str],
    init_delay_seconds: float = 0.0
) -> bool:
    """
    Load a script into a Frida session and wire it to the global message buffer.

    Args:
        session: The Frida session to load the script into
        initial_script: The JavaScript script to load
        init_delay_seconds: Delay in seconds before returning (for initialization)

    Returns:
        True if script was loaded, False if initial_script was None
    """
    if not initial_script:
        logger.debug("No initial script provided")
        return False

    try:
        wrapped_script = wrap_script_for_mcp(initial_script)
        script = session.create_script(wrapped_script)

        # Clear global buffer
        try:
            while len(messages_buffer) > 0:
                messages_buffer.popleft()
        except Exception as e:
            logger.warning(f"Failed to clear message buffer: {e}")

        handler, _ = create_message_collector(messages_buffer)
        script.on('message', handler)
        script.load()

        # Keep reference so script isn't garbage-collected
        active_scripts.append(script)
        logger.info("Script loaded successfully")

        if init_delay_seconds and init_delay_seconds > 0:
            await asyncio.sleep(init_delay_seconds)

        return True
    except Exception as e:
        logger.error(f"Failed to load script: {e}")
        return False

async def ensure_device_connected(device_id: Optional[str] = None) -> bool:
    """
    Ensure device is connected using multiple connection strategies.

    Connection order:
    1. Explicit device_id parameter
    2. device_id from CONFIG
    3. USB device
    4. Remote device via localhost:server_port

    Args:
        device_id: Optional explicit device ID to connect to

    Returns:
        True if device is connected, False otherwise
    """
    global device

    # Check if already connected
    if device:
        try:
            # Test if device is still connected
            _ = device.id
            logger.debug("Device already connected")
            return True
        except Exception as e:
            logger.warning(f"Device connection lost: {e}")
            device = None

    # Try explicit device_id first
    device_id_to_use = device_id or CONFIG.get("device_id")
    if device_id_to_use:
        try:
            device = frida.get_device(device_id_to_use)
            logger.info(f"Connected to device: {device_id_to_use}")
            return True
        except Exception as e:
            logger.debug(f"Failed to connect to device {device_id_to_use}: {e}")

    # Try USB device
    try:
        device = frida.get_usb_device(timeout=5)
        logger.info(f"Connected to USB device: {device.name}")
        return True
    except Exception as e:
        logger.debug(f"Failed to connect to USB device: {e}")

    # Try remote device via localhost
    try:
        port = int(CONFIG.get("server_port") or 27042)
        # Ensure ADB port forwarding
        try:
            dm = DeviceManager()
            dm.setup_port_forward(str(port))
            time.sleep(0.5)
        except Exception as e:
            logger.debug(f"Port forwarding setup failed: {e}")

        manager = frida.get_device_manager()
        device_remote = manager.add_remote_device(f"127.0.0.1:{port}")
        if device_remote:
            device = device_remote
            logger.info(f"Connected to remote device at 127.0.0.1:{port}")
            return True
    except Exception as e:
        logger.debug(f"Failed to connect to remote device: {e}")

    logger.error("Failed to connect to any device")
    return False


def _resolve_server_path_from_config() -> str:
    """
    Resolve the frida-server path from configuration.

    Priority:
    1. server_path + server_name (if both provided)
    2. server_path (if provided)
    3. /data/local/tmp + server_name (if name provided)
    4. Default: /data/local/tmp/frida-server

    Returns:
        The resolved frida-server path
    """
    base = (CONFIG.get("server_path") or "").rstrip("/")
    name = CONFIG.get("server_name")

    if base and name:
        path = f"{base}/{name}"
    elif base:
        path = base
    elif name:
        path = f"/data/local/tmp/{name}"
    else:
        path = "/data/local/tmp/frida-server"

    logger.debug(f"Resolved server path: {path}")
    return path


@app.tool()
async def start_frida_server() -> Dict[str, Any]:
    """
    Start frida-server on the connected Android device.

    Uses configuration from config.json (server_path, server_name, server_port).

    Returns:
        Dictionary with keys:
        - status: "success" or "error"
        - path: Path to frida-server on device
        - port: Port number used
        - message: Status message
    """
    try:
        dm = DeviceManager()

        # If already running, no-op
        if dm.check_frida_status(silent=True):
            logger.info("Frida server already running")
            return {
                "status": "success",
                "message": "frida-server already running",
            }

        path = _resolve_server_path_from_config()
        port_value = int(CONFIG.get("server_port") or 27042)
        ok = dm.start_frida_server(server_path=path, port=str(port_value))

        if ok:
            logger.info(f"Frida server started at {path}:{port_value}")
        else:
            logger.error(f"Failed to start frida server at {path}:{port_value}")

        return {
            "status": "success" if ok else "error",
            "path": path,
            "port": port_value,
            "message": "frida-server started" if ok else "failed to start frida-server"
        }
    except Exception as e:
        logger.error(f"Error starting frida server: {e}")
        return {"status": "error", "message": str(e)}


@app.tool()
async def stop_frida_server() -> Dict[str, Any]:
    """
    Stop frida-server on the connected Android device.

    Returns:
        Dictionary with keys:
        - status: "success" or "error"
        - message: Status message
    """
    try:
        dm = DeviceManager()

        # If not running, no-op
        if not dm.check_frida_status(silent=True):
            logger.info("Frida server already stopped")
            return {"status": "success", "message": "frida-server already stopped"}

        ok = dm.stop_frida_server()

        if ok:
            logger.info("Frida server stopped")
        else:
            logger.error("Failed to stop frida server")

        return {
            "status": "success" if ok else "error",
            "message": "frida-server stopped" if ok else "failed to stop frida-server"
        }
    except Exception as e:
        logger.error(f"Error stopping frida server: {e}")
        return {"status": "error", "message": str(e)}


@app.tool()
async def check_frida_status() -> Dict[str, Any]:
    """
    Check if frida-server is running on the connected device.

    Returns:
        Dictionary with keys:
        - status: "success" or "error"
        - running: Boolean indicating if frida-server is running
    """
    try:
        dm = DeviceManager()
        running = bool(dm.check_frida_status(silent=True))
        logger.info(f"Frida server running: {running}")
        return {"status": "success", "running": running}
    except Exception as e:
        logger.error(f"Error checking frida status: {e}")
        return {"status": "error", "message": str(e)}


@app.tool()
async def get_messages(max_messages: int = 100) -> Dict[str, Any]:
    """
    Retrieve messages from the global message buffer (non-consuming mode).

    Args:
        max_messages: Maximum number of messages to return (default 100).
                     If 0 or negative, returns empty list.

    Returns:
        Dictionary with keys:
        - status: "success" or "error"
        - messages: List of message strings
        - remaining: Total number of messages in buffer
    """
    try:
        if max_messages is None or max_messages < 0:
            max_messages = 0

        buffer = messages_buffer
        if not buffer or len(buffer) == 0:
            logger.debug("Message buffer is empty")
            return {
                "status": "success",
                "messages": [],
                "remaining": 0
            }

        snapshot = list(buffer)
        if max_messages > 0:
            snapshot = snapshot[-max_messages:]
        else:
            snapshot = []

        logger.debug(f"Retrieved {len(snapshot)} messages from buffer")
        return {
            "status": "success",
            "messages": snapshot,
            "remaining": len(buffer)
        }
    except Exception as e:
        logger.error(f"Error retrieving messages: {e}")
        return {"status": "error", "message": str(e)}


@app.tool()
async def get_frontmost_application() -> Dict[str, Any]:
    """
    Get information about the currently active (frontmost) application.

    Returns:
        Dictionary with keys:
        - status: "success" or "error"
        - application: Dict with identifier, name, pid (or None if not found)
        - message: Optional status message
    """
    if not await ensure_device_connected():
        logger.error("Failed to connect to device for frontmost app query")
        return {
            "status": "error",
            "message": "Failed to connect to device. Ensure frida-server is running."
        }

    try:
        frontmost = device.get_frontmost_application()
        if frontmost:
            app_info = {
                "identifier": frontmost.identifier,
                "name": frontmost.name,
                "pid": frontmost.pid
            }
            logger.info(f"Frontmost application: {app_info['name']} ({app_info['identifier']})")
            return {
                "status": "success",
                "application": app_info
            }
        else:
            logger.warning("No frontmost application found")
            return {
                "status": "success",
                "application": None,
                "message": "No frontmost application found"
            }
    except Exception as e:
        logger.error(f"Error getting frontmost application: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@app.tool()
async def list_applications() -> Dict[str, Any]:
    """
    List all installed applications on the device.

    Returns both running and non-running applications.

    Returns:
        Dictionary with keys:
        - status: "success" or "error"
        - count: Number of applications
        - applications: List of dicts with identifier, name, pid
    """
    if not await ensure_device_connected():
        logger.error("Failed to connect to device for app listing")
        return {
            "status": "error",
            "message": "Failed to connect to device. Ensure frida-server is running."
        }

    try:
        applications = device.enumerate_applications()
        app_list = []
        for app in applications:
            app_list.append({
                "identifier": app.identifier,
                "name": app.name,
                "pid": app.pid if hasattr(app, 'pid') else None
            })

        # Sort by name for easier reading
        app_list.sort(key=lambda x: x["name"].lower())

        logger.info(f"Listed {len(app_list)} applications")
        return {
            "status": "success",
            "count": len(app_list),
            "applications": app_list
        }
    except Exception as e:
        logger.error(f"Error listing applications: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@app.tool()
async def attach(
    target: str,
    initial_script: Optional[str] = None
) -> Dict[str, Any]:
    """
    Attach to a running process and optionally inject a script.

    Args:
        target: Process ID (as string) or package name
        initial_script: Optional Frida JavaScript to inject

    Returns:
        Dictionary with keys:
        - status: "success" or "error"
        - pid: Process ID (if successful)
        - target: The target identifier provided
        - name: Application name
        - script_loaded: Whether script was loaded
        - message: Status message
    """
    global session

    # Clean up old session if exists
    if session:
        try:
            session.detach()
            logger.info("Previous session detached")
        except Exception as e:
            logger.warning(f"Failed to detach previous session: {e}")
        session = None

    # Ensure device is connected
    if not await ensure_device_connected():
        logger.error("Device not connected for attach operation")
        return {
            "status": "error",
            "message": "Failed to connect to device. Ensure frida-server is running."
        }

    if not target or not target.strip():
        logger.error("Empty target provided to attach")
        return {
            "status": "error",
            "message": "Target cannot be empty"
        }

    target = target.strip()

    try:
        # Determine PID
        if target.isdigit():
            pid = int(target)
            app_name = target
            logger.info(f"Attaching to PID: {pid}")
        else:
            # Find app by package name
            logger.info(f"Looking for running app: {target}")
            applications = device.enumerate_applications()
            target_app = None

            for app in applications:
                if app.identifier == target and app.pid and app.pid > 0:
                    target_app = app
                    break

            if not target_app:
                logger.error(f"Unable to find running app: {target}")
                return {
                    "status": "error",
                    "message": f"Unable to find running app: {target}"
                }

            pid = target_app.pid
            app_name = target_app.name
            logger.info(f"Found app {app_name} with PID {pid}")

        # Attach to the process
        session = device.attach(pid)
        _bind_session_events(session)
        logger.info(f"Successfully attached to PID {pid}")

        # If initial script provided, inject it immediately
        script_loaded = False
        if initial_script:
            try:
                script_loaded = await _load_script_with_global_buffer(session, initial_script)
                if script_loaded:
                    logger.info("Script injected successfully")
            except Exception as e:
                logger.error(f"Script load error: {e}")
                _frida_log(f"script load error: {e}")
                return {"status": "error", "message": str(e)}

        result = {
            "status": "success",
            "pid": pid,
            "target": target,
            "name": app_name if not target.isdigit() else target,
            "script_loaded": script_loaded,
            "message": "Attached successfully."
        }

        return result

    except Exception as e:
        logger.error(f"Error attaching to target {target}: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


@app.tool()
async def spawn(
    package_name: str,
    initial_script: Optional[str] = None
) -> Dict[str, Any]:
    """
    Spawn an application in suspended state, attach to it, and optionally inject a script.

    The app is spawned in suspended state, allowing script injection before resumption.

    Args:
        package_name: The package name of the application to spawn
        initial_script: Optional Frida JavaScript to inject before resuming

    Returns:
        Dictionary with keys:
        - status: "success" or "error"
        - pid: Process ID of spawned app
        - package: Package name
        - script_loaded: Whether script was loaded
        - message: Status message
    """
    global session

    # Clean up old session if exists
    if session:
        try:
            session.detach()
            logger.info("Previous session detached")
        except Exception as e:
            logger.warning(f"Failed to detach previous session: {e}")
        session = None

    # Ensure device is connected
    if not await ensure_device_connected():
        logger.error("Device not connected for spawn operation")
        return {
            "status": "error",
            "message": "Failed to connect to device. Ensure frida-server is running."
        }

    try:
        # Spawn the app in suspended state
        logger.info(f"Spawning app: {package_name}")
        pid = device.spawn(package_name)
        logger.info(f"App spawned with PID: {pid}")

        session = device.attach(pid)
        _bind_session_events(session)
        logger.info(f"Attached to spawned process {pid}")

        # If initial script provided, inject it before resuming
        script_loaded = False
        if initial_script:
            try:
                script_loaded = await _load_script_with_global_buffer(
                    session, initial_script, init_delay_seconds=0.1
                )
                if script_loaded:
                    logger.info("Script injected before app resume")
            except Exception as e:
                logger.error(f"Script load error: {e}")
                _frida_log(f"script load error: {e}")
                return {"status": "error", "message": str(e)}

        # Resume the app
        device.resume(pid)
        logger.info(f"App resumed with PID: {pid}")

        # Logs are collected asynchronously in global buffer

        result = {
            "status": "success",
            "pid": pid,
            "package": package_name,
            "script_loaded": script_loaded,
            "message": "App spawned successfully."
        }

        return result

    except Exception as e:
        logger.error(f"Error spawning app {package_name}: {e}")
        return {
            "status": "error",
            "message": str(e)
        }





if __name__ == "__main__":
    app.run()