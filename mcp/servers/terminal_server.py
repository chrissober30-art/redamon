"""
RedAmon Terminal Server — WebSocket PTY for Kali Sandbox

Provides a WebSocket endpoint that spawns an interactive bash shell
with full PTY support. Used by the RedAmon Terminal tab in the webapp.

Runs on port 8016 inside the kali-sandbox container.
"""

import asyncio
import fcntl
import os
import pty
import select
import signal
import struct
import termios
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [terminal] %(message)s")
logger = logging.getLogger("terminal-server")

PORT = int(os.getenv("TERMINAL_WS_PORT", "8016"))


async def _pty_session(ws):
    """Handle a single WebSocket connection with a PTY bash shell."""
    master_fd, slave_fd = pty.openpty()
    pid = os.fork()

    if pid == 0:
        # Child process — become the shell
        os.setsid()
        os.close(master_fd)

        # Set slave as controlling terminal
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

        os.dup2(slave_fd, 0)
        os.dup2(slave_fd, 1)
        os.dup2(slave_fd, 2)
        if slave_fd > 2:
            os.close(slave_fd)

        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        env["SHELL"] = "/bin/bash"
        env["PS1"] = r"\[\033[1;31m\]redamon\[\033[0m\]@\[\033[1;36m\]kali\[\033[0m\]:\[\033[1;33m\]\w\[\033[0m\]$ "

        os.execvpe("/bin/bash", ["/bin/bash", "--login"], env)
        # Never reached
        os._exit(1)

    # Parent process — bridge WebSocket ↔ PTY
    os.close(slave_fd)

    # Set initial terminal size
    _set_pty_size(master_fd, 24, 80)

    closed = False

    async def read_pty():
        """Read from PTY master and forward to WebSocket."""
        nonlocal closed
        while not closed:
            try:
                await asyncio.sleep(0.01)
                if closed:
                    break
                r, _, _ = select.select([master_fd], [], [], 0.05)
                if r:
                    try:
                        data = os.read(master_fd, 4096)
                    except OSError:
                        break
                    if not data:
                        break
                    try:
                        await ws.send(data)
                    except Exception:
                        break
            except Exception:
                break

    async def write_pty():
        """Read from WebSocket and forward to PTY master."""
        nonlocal closed
        try:
            async for message in ws:
                if closed:
                    break

                if isinstance(message, bytes):
                    os.write(master_fd, message)
                elif isinstance(message, str):
                    # Handle JSON control messages for resize
                    try:
                        msg = json.loads(message)
                        if msg.get("type") == "resize":
                            rows = msg.get("rows", 24)
                            cols = msg.get("cols", 80)
                            _set_pty_size(master_fd, rows, cols)
                            continue
                    except (json.JSONDecodeError, TypeError):
                        pass
                    os.write(master_fd, message.encode("utf-8"))
        except Exception:
            pass
        finally:
            closed = True

    try:
        reader_task = asyncio.create_task(read_pty())
        writer_task = asyncio.create_task(write_pty())
        await asyncio.wait(
            [reader_task, writer_task], return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        closed = True
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            os.close(master_fd)
        except OSError:
            pass
        # Wait briefly for child to exit, then force-kill if still alive
        for _ in range(10):
            try:
                result = os.waitpid(pid, os.WNOHANG)
                if result[0] != 0:
                    break
            except ChildProcessError:
                break
            await asyncio.sleep(0.1)
        else:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass


def _set_pty_size(fd: int, rows: int, cols: int):
    """Set the PTY window size."""
    try:
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
    except (OSError, ValueError):
        pass


def main():
    """Start the WebSocket terminal server."""
    import websockets

    logger.info(f"Starting terminal WebSocket server on port {PORT}")

    async def _run():
        async with websockets.serve(
            _pty_session,
            "0.0.0.0",
            PORT,
            ping_interval=30,
            ping_timeout=60,
            max_size=2**20,
        ):
            logger.info(f"Terminal server listening on ws://0.0.0.0:{PORT}")
            await asyncio.Future()  # Run forever

    asyncio.run(_run())


if __name__ == "__main__":
    main()
