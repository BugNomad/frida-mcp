"""
Device Manager Module

Handles Android device connection, frida-server management, and ADB operations.
Provides utilities for managing Frida server lifecycle and device communication.
"""

import subprocess
import time
import logging
from typing import Optional, Callable
import frida

logger = logging.getLogger(__name__)


class DeviceManager:
    """Manages Android device connection and frida-server lifecycle."""

    def __init__(self, log_callback: Optional[Callable[[str], None]] = None) -> None:
        """
        Initialize DeviceManager.

        Args:
            log_callback: Optional callback function for logging messages
        """
        self.device: Optional[frida.core.Device] = None
        self.log = log_callback or self._default_log
        self.frida_server_path: str = "/data/local/tmp/frida-server"

    @staticmethod
    def _default_log(message: str) -> None:
        """Default logging function."""
        logger.info(message)
    
    def check_adb(self) -> bool:
        """
        Check if ADB is available and a device is connected.

        Returns:
            True if ADB is available and device is connected, False otherwise
        """
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if "device" in result.stdout and not result.stdout.strip().endswith("devices"):
                logger.debug("ADB device found")
                return True
            else:
                logger.warning("No Android device connected via ADB")
                return False
        except FileNotFoundError:
            logger.error("ADB not found in PATH")
            return False
        except subprocess.TimeoutExpired:
            logger.error("ADB command timed out")
            return False
        except Exception as e:
            logger.error(f"Error checking ADB: {e}")
            return False
    
    def setup_port_forward(self, port: str = "27042") -> bool:
        """
        Setup ADB port forwarding.

        Args:
            port: Port number to forward (default: 27042)

        Returns:
            True if port forwarding was set up successfully, False otherwise
        """
        if not self.check_adb():
            logger.error("ADB not available for port forwarding")
            return False

        try:
            # Remove existing port forwarding
            subprocess.run(
                ["adb", "forward", "--remove-all"],
                capture_output=True,
                timeout=5
            )

            # Setup new port forwarding
            result = subprocess.run(
                ["adb", "forward", f"tcp:{port}", f"tcp:{port}"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                logger.info(f"Port forwarding established: localhost:{port} -> device:{port}")
                return True
            else:
                logger.error(f"Failed to setup port forwarding: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Port forwarding setup timed out")
            return False
        except Exception as e:
            logger.error(f"Error setting up port forwarding: {e}")
            return False
    
    def connect_usb_device(self, port: str = "27042") -> bool:
        """
        Connect to USB device via Frida.

        Tries direct USB connection first, then falls back to port forwarding.

        Args:
            port: Port number for forwarding (default: 27042)

        Returns:
            True if connection successful, False otherwise
        """
        try:
            # Setup port forwarding first
            if self.setup_port_forward(port):
                time.sleep(1)

            try:
                # Try direct USB connection first
                self.device = frida.get_usb_device(timeout=5)
                logger.info(f"Connected to USB device: {self.device.name}")
                return True
            except Exception as e:
                logger.debug(f"Direct USB connection failed: {e}")
                # If direct USB fails, try via forwarded port
                logger.info("Trying connection via forwarded port...")
                device_manager = frida.get_device_manager()
                self.device = device_manager.add_remote_device(f"127.0.0.1:{port}")
                logger.info(f"Connected via forwarded port: 127.0.0.1:{port}")
                return True

        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            logger.error("Tip: Make sure frida-server is running on device")
            return False
    
    def connect_remote_device(self, host: str) -> bool:
        """
        Connect to remote device.

        Args:
            host: Host address (e.g., "192.168.1.100:27042")

        Returns:
            True if connection successful, False otherwise
        """
        try:
            device_manager = frida.get_device_manager()
            self.device = device_manager.add_remote_device(host)
            logger.info(f"Connected to remote device: {host}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to remote device {host}: {e}")
            return False
    
    def start_frida_server(
        self,
        server_path: Optional[str] = None,
        port: str = "27042"
    ) -> bool:
        """
        Start frida-server on the device.

        Args:
            server_path: Optional custom path to frida-server binary
            port: Port number for frida-server (default: 27042)

        Returns:
            True if server started successfully, False otherwise
        """
        if not self.check_adb():
            logger.error("ADB not available for starting frida-server")
            return False

        if server_path:
            self.frida_server_path = server_path

        logger.info(f"Starting frida-server at {self.frida_server_path}...")

        # Auto setup port forwarding
        self.setup_port_forward(port)

        # Kill existing frida-server processes
        try:
            subprocess.run(
                ["adb", "shell", "su", "-c", "pkill", "-f", "frida"],
                capture_output=True,
                timeout=5
            )
            subprocess.run(
                ["adb", "shell", "su", "-c", "pkill", "-f", self.frida_server_path.split('/')[-1]],
                capture_output=True,
                timeout=5
            )
            time.sleep(1)
            logger.debug("Killed existing frida processes")
        except Exception as e:
            logger.warning(f"Error killing existing processes: {e}")
        
        # Check if file exists and set permissions
        try:
            check_result = subprocess.run(
                ["adb", "shell", "su", "-c", f"ls -la {self.frida_server_path}"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if "No such file" in check_result.stderr or "No such file" in check_result.stdout:
                logger.error(f"File not found: {self.frida_server_path}")
                logger.error("Please check the path and ensure frida-server is pushed to device")
                return False

            # Set execute permission
            subprocess.run(
                ["adb", "shell", "su", "-c", f"chmod 755 {self.frida_server_path}"],
                capture_output=True,
                timeout=5
            )
            logger.debug("Set execute permission on frida-server")

            # Start frida-server with different methods based on path
            if "/tmp" in self.frida_server_path or "/data/local/tmp" in self.frida_server_path:
                cmd = f"{self.frida_server_path} -D"
            else:
                cmd = f"cd {'/'.join(self.frida_server_path.split('/')[:-1])} && ./{self.frida_server_path.split('/')[-1]} -D"

            # Start in background
            start_result = subprocess.run(
                ["adb", "shell"],
                input=f"su -c '{cmd} &'\nexit\n",
                capture_output=True,
                text=True,
                timeout=3
            )

            time.sleep(0.5)  # Wait for server to start

            # Check if server is running
            if self.check_frida_status(silent=True):
                logger.info("Frida server started successfully")
                return True
            else:
                # Try alternative method
                logger.info("Trying alternative start method (daemonize)...")

                try:
                    subprocess.run(
                        ["adb", "shell", "su", "-c", f"daemonize {self.frida_server_path}"],
                        capture_output=True,
                        timeout=2
                    )

                    time.sleep(2)
                    if self.check_frida_status(silent=True):
                        logger.info("Frida server started successfully (daemonize)")
                        return True
                except subprocess.TimeoutExpired:
                    logger.debug("Daemonize command timed out")

                logger.error("Failed to start frida server")
                if start_result.stdout:
                    logger.error(f"Debug info: {start_result.stdout}")
                if start_result.stderr:
                    logger.error(f"Error: {start_result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.warning("Server startup timed out, checking status...")
            time.sleep(2)
            if self.check_frida_status(silent=True):
                logger.info("Frida server started successfully")
                return True
            else:
                logger.error("Server may be starting, please check status")
                return False

        except Exception as e:
            logger.error(f"Error starting frida server: {e}")
            return False
    
    def stop_frida_server(self) -> bool:
        """
        Stop frida-server on the device.

        Returns:
            True if server was stopped successfully, False otherwise
        """
        if not self.check_adb():
            logger.error("ADB not available for stopping frida-server")
            return False

        logger.info("Stopping frida-server...")

        try:
            # Kill by process name patterns
            subprocess.run(
                ["adb", "shell", "su", "-c", "pkill", "-f", "frida"],
                capture_output=True,
                timeout=5
            )
            subprocess.run(
                ["adb", "shell", "su", "-c", "pkill", "-f", self.frida_server_path.split('/')[-1]],
                capture_output=True,
                timeout=5
            )

            logger.info("Frida server stopped")
            return True

        except subprocess.TimeoutExpired:
            logger.error("Stop command timed out")
            return False
        except Exception as e:
            logger.error(f"Error stopping frida server: {e}")
            return False
    
    def check_frida_status(self, silent: bool = False) -> bool:
        """
        Check if frida-server is running on the device.

        Args:
            silent: If True, suppress logging output

        Returns:
            True if frida-server is running, False otherwise
        """
        if not self.check_adb():
            if not silent:
                logger.warning("ADB not available for status check")
            return False

        server_name = self.frida_server_path.split('/')[-1]

        try:
            result = subprocess.run(
                ["adb", "shell", "ps", "-A"],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Check for frida or custom server name
            is_running = "frida" in result.stdout.lower() or server_name in result.stdout

            if is_running:
                if not silent:
                    logger.info("Frida server is running")
                return True
            else:
                if not silent:
                    logger.warning("Frida server is not running")
                return False

        except subprocess.TimeoutExpired:
            if not silent:
                logger.error("Status check timed out")
            return False
        except Exception as e:
            if not silent:
                logger.error(f"Error checking frida status: {e}")
            return False
    
    def execute_custom_command(self, command: str) -> bool:
        """
        Execute custom command to start frida-server.

        Args:
            command: The shell command to execute

        Returns:
            True if command executed and server started, False otherwise
        """
        if not self.check_adb():
            logger.error("ADB not available for custom command")
            return False

        logger.info(f"Executing manual command: {command}")

        try:
            # First kill existing processes
            subprocess.run(
                ["adb", "shell", "su", "-c", "pkill", "-f", "frida"],
                capture_output=True,
                timeout=5
            )
            time.sleep(1)

            # Execute the custom command
            result = subprocess.run(
                ["adb", "shell"],
                input=f"{command}\nexit\n",
                capture_output=True,
                text=True,
                timeout=5
            )

            logger.info("Command executed, checking status...")
            time.sleep(2)

            if self.check_frida_status(silent=True):
                logger.info("Frida server started successfully via manual command")
                return True
            else:
                logger.error("Server not detected")
                if result.stdout:
                    logger.error(f"Output: {result.stdout}")
                if result.stderr:
                    logger.error(f"Error: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.warning("Command timeout - server may be running in background")
            time.sleep(2)
            if self.check_frida_status(silent=True):
                logger.info("Frida server started successfully")
                return True
            return False

        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return False

    def get_applications(self) -> list:
        """
        Get list of applications on the device.

        Returns:
            List of applications, or empty list if device not connected
        """
        if not self.device:
            logger.warning("No device connected for app enumeration")
            return []

        try:
            apps = self.device.enumerate_applications()
            logger.debug(f"Enumerated {len(apps)} applications")
            return apps
        except Exception as e:
            logger.error(f"Error listing applications: {e}")
            return []

    def spawn_application(self, package_name: str) -> int:
        """
        Spawn an application.

        Args:
            package_name: Package name of the application

        Returns:
            Process ID of spawned application

        Raises:
            Exception: If no device is connected
        """
        if not self.device:
            raise Exception("No device connected")

        logger.info(f"Spawning application: {package_name}")
        pid = self.device.spawn([package_name])
        logger.info(f"Application spawned with PID: {pid}")
        return pid

    def resume_application(self, pid: int) -> None:
        """
        Resume a spawned application.

        Args:
            pid: Process ID to resume

        Raises:
            Exception: If no device is connected
        """
        if not self.device:
            raise Exception("No device connected")

        logger.info(f"Resuming application with PID: {pid}")
        self.device.resume(pid)

    def attach_to_process(self, pid: int) -> frida.core.Session:
        """
        Attach to a process.

        Args:
            pid: Process ID to attach to

        Returns:
            Frida session object

        Raises:
            Exception: If no device is connected
        """
        if not self.device:
            raise Exception("No device connected")

        logger.info(f"Attaching to process with PID: {pid}")
        session = self.device.attach(pid)
        return session