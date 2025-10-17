"""
Cross-platform utility to find and kill processes using a specific port.

Supports Windows, macOS, and Linux.
"""

import argparse
import subprocess
import sys
import re
import platform
from typing import Set


def find_pids_on_port_windows(port: int) -> Set[int]:
    """Find PIDs using a port on Windows."""
    try:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True,
            text=True,
            check=True,
            shell=False
        )
    except Exception as e:
        print(f"Failed to run netstat: {e}")
        return set()

    pids: Set[int] = set()
    # Match lines with local address containing :<port>, PID is last column
    pattern = re.compile(rf"^(TCP|UDP)\s+\S*:{port}\b.*\s(\d+)\s*$", re.IGNORECASE)
    for line in result.stdout.splitlines():
        line = line.strip()
        m = pattern.search(line)
        if m:
            try:
                pids.add(int(m.group(2)))
            except ValueError:
                pass
    return pids


def find_pids_on_port_unix(port: int) -> Set[int]:
    """Find PIDs using a port on Unix-like systems (macOS, Linux)."""
    pids: Set[int] = set()

    try:
        # Try lsof first (more reliable)
        result = subprocess.run(
            ["lsof", "-i", f":{port}"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            # Parse lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
            for line in result.stdout.splitlines()[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        pids.add(int(parts[1]))
                    except ValueError:
                        pass
            return pids
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback to netstat
    try:
        result = subprocess.run(
            ["netstat", "-tlnp"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            # Parse netstat output
            pattern = re.compile(rf".*:{port}\s+.*\s(\d+)/")
            for line in result.stdout.splitlines():
                m = pattern.search(line)
                if m:
                    try:
                        pids.add(int(m.group(1)))
                    except ValueError:
                        pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return pids


def find_pids_on_port(port: int) -> Set[int]:
    """Find PIDs using a port (cross-platform)."""
    system = platform.system()

    if system == "Windows":
        return find_pids_on_port_windows(port)
    else:  # macOS, Linux, etc.
        return find_pids_on_port_unix(port)


def kill_pid_windows(pid: int) -> bool:
    """Kill a process on Windows."""
    try:
        proc = subprocess.run(
            ["taskkill", "/PID", str(pid), "/F"],
            capture_output=True,
            text=True,
            shell=False
        )
        if proc.returncode == 0:
            print(f"Killed PID {pid}")
            return True
        else:
            print(f"Failed to kill PID {pid}: {proc.stdout or proc.stderr}".strip())
            return False
    except Exception as e:
        print(f"Error killing PID {pid}: {e}")
        return False


def kill_pid_unix(pid: int) -> bool:
    """Kill a process on Unix-like systems."""
    try:
        subprocess.run(
            ["kill", "-9", str(pid)],
            capture_output=True,
            check=True
        )
        print(f"Killed PID {pid}")
        return True
    except subprocess.CalledProcessError:
        print(f"Failed to kill PID {pid}: Process not found or permission denied")
        return False
    except Exception as e:
        print(f"Error killing PID {pid}: {e}")
        return False


def kill_pid(pid: int) -> bool:
    """Kill a process (cross-platform)."""
    system = platform.system()

    if system == "Windows":
        return kill_pid_windows(pid)
    else:  # macOS, Linux, etc.
        return kill_pid_unix(pid)

def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Kill processes listening/using a given port (cross-platform)."
    )
    parser.add_argument("port", type=int, help="Port number, e.g., 27042")
    args = parser.parse_args()

    if not (1 <= args.port <= 65535):
        print("Invalid port. Must be in 1..65535")
        sys.exit(2)

    print(f"Searching for processes using port {args.port}...")
    pids = find_pids_on_port(args.port)

    if not pids:
        print(f"No processes found using port {args.port}.")
        return

    print(f"Found PIDs on port {args.port}: {', '.join(map(str, sorted(pids)))}")
    success = True
    for pid in sorted(pids):
        ok = kill_pid(pid)
        success = success and ok

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()