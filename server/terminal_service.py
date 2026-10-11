import asyncio
import logging
import os
import sys
import time
from typing import Optional

from fastapi import WebSocket

from .config import DEFAULT_SHELL, TERM_COLS, TERM_ROWS

logger = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"

# Track all active sessions for cleanup on shutdown
_active_sessions: list["TerminalSession"] = []


def get_active_session_count() -> int:
    """Return the number of terminal sessions that are currently running."""
    return sum(1 for session in _active_sessions if session._running)


# =========================================================================
#  Windows: use pywinpty for a real ConPTY, fall back to subprocess pipes
# =========================================================================

if IS_WINDOWS:
    try:
        # pywinpty is the package name, but its import module is ``winpty``.
        from winpty import PtyProcess
        _HAS_WINPTY = True
        _WINPTY_LEGACY = False
        logger.info("Windows PTY support: pywinpty available (PtyProcess)")
    except ImportError:
        try:
            # Older pywinpty versions used this name
            from winpty import PTY as _OldPTY  # type: ignore
            _HAS_WINPTY = True
            _WINPTY_LEGACY = True
            logger.info("Windows PTY support: winpty (legacy API)")
        except ImportError:
            _HAS_WINPTY = False
            _WINPTY_LEGACY = False
            logger.warning(
                "pywinpty not installed. Terminal will use subprocess pipes (limited "
                "functionality — no colors, no tab completion, no TUI apps). "
                "Install it for full PTY support: pip install pywinpty"
            )
else:
    _WINPTY_LEGACY = False


class TerminalSession:
    """
    Manages a single terminal session bridged to a WebSocket.

    On Unix: uses pty.fork() for a real pseudo-terminal.
    On Windows: uses pywinpty (PtyProcess) if available, otherwise falls
    back to subprocess pipes with cmd.exe / powershell.exe.
    """

    def __init__(
        self,
        ws: WebSocket,
        username: str,
        cols: int = TERM_COLS,
        rows: int = TERM_ROWS,
    ):
        self.ws = ws
        self.username = username
        self.cols = max(2, min(int(cols), 1000))
        self.rows = max(1, min(int(rows), 500))
        self._running = False
        self._read_task: Optional[asyncio.Task] = None
        self._created_at: Optional[float] = None

        # Platform-specific handles
        self.pid: Optional[int] = None
        self.fd: Optional[int] = None          # Unix PTY fd
        self._process = None                    # Windows subprocess / fallback
        self._conpty = None                     # Windows ConPTY (pywinpty)

    # -----------------------------------------------------------------
    #  START
    # -----------------------------------------------------------------
    async def start(self):
        self._created_at = time.monotonic()
        if IS_WINDOWS:
            await self._start_windows()
        else:
            await self._start_unix()

    # -- Unix ----------------------------------------------------------
    async def _start_unix(self):
        import fcntl
        import pty
        import select
        import struct
        import termios

        self.pid, self.fd = pty.fork()

        if self.pid == 0:
            env = os.environ.copy()
            env["TERM"] = "xterm-256color"
            env["SHELL"] = DEFAULT_SHELL
            os.execvpe(DEFAULT_SHELL, [DEFAULT_SHELL], env)
            os._exit(1)

        self._running = True
        self._unix_set_pty_size(self.cols, self.rows)
        self._read_task = asyncio.create_task(self._unix_read_loop())
        _active_sessions.append(self)
        logger.info(
            "Terminal session started for user '%s' (pid=%d, unix pty, sessions=%d)",
            self.username, self.pid, len(_active_sessions),
        )

    def _unix_set_pty_size(self, cols, rows):
        import fcntl
        import struct
        import termios
        if self.fd is not None:
            try:
                winsize = struct.pack("HHHH", rows, cols, 0, 0)
                fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
            except OSError as e:
                logger.warning("Failed to resize PTY: %s", e)

    async def _unix_read_loop(self):
        import select
        while self._running:
            try:
                r, _, _ = select.select([self.fd], [], [], 0.1)
                if r:
                    data = os.read(self.fd, 65536)
                    if data:
                        await self.ws.send_bytes(data)
                    else:
                        self._running = False
                        break
            except OSError:
                self._running = False
                break
            except Exception as e:
                logger.error("PTY read error for user '%s': %s", self.username, e)
                self._running = False
                break
        try:
            await self.ws.send_bytes(b"\r\n[Session ended]\r\n")
        except Exception:
            pass
        await self.cleanup()

    # -- Windows --------------------------------------------------------
    async def _start_windows(self):
        if _HAS_WINPTY:
            if _WINPTY_LEGACY:
                await self._start_winpty_legacy()
            else:
                await self._start_winpty()
        else:
            await self._start_windows_fallback()

    async def _start_winpty(self):
        """Start terminal using pywinpty 2.0+ PtyProcess API."""
        from winpty import PtyProcess

        # Determine the shell to launch
        shell_cmd = self._get_windows_shell()

        try:
            # PtyProcess uses (rows, cols), unlike the legacy PTY API.
            self._conpty = PtyProcess.spawn(
                shell_cmd, dimensions=(self.rows, self.cols)
            )
            self.pid = self._conpty.pid
        except Exception as e:
            logger.error("pywinpty PtyProcess.spawn failed: %s, falling back to pipes", e)
            self._conpty = None
            await self._start_windows_fallback()
            return

        self._running = True
        self._read_task = asyncio.create_task(self._winpty_read_loop())
        _active_sessions.append(self)
        logger.info(
            "Terminal session started for user '%s' (pid=%d, pywinpty PtyProcess, sessions=%d)",
            self.username, self.pid, len(_active_sessions),
        )

    async def _start_winpty_legacy(self):
        """Start terminal using older winpty.PTY API (pywinpty < 2.0)."""
        import winpty  # type: ignore

        shell_cmd = self._get_windows_shell()

        try:
            self._conpty = winpty.PTY(self.cols, self.rows)
            self._conpty.spawn(shell_cmd)
            self.pid = getattr(self._conpty, 'pid', None)
        except Exception as e:
            logger.error("winpty.PTY spawn failed: %s, falling back to pipes", e)
            self._conpty = None
            await self._start_windows_fallback()
            return

        self._running = True
        self._read_task = asyncio.create_task(self._winpty_read_loop())
        _active_sessions.append(self)
        logger.info(
            "Terminal session started for user '%s' (pid=%s, winpty legacy, sessions=%d)",
            self.username, self.pid, len(_active_sessions),
        )

    def _get_windows_shell(self) -> str:
        """Determine the best shell command for Windows."""
        import shutil
        shell = DEFAULT_SHELL

        # If the configured shell exists, use it directly
        if shutil.which(shell):
            return shell

        # Fallback chain: PowerShell → pwsh → cmd.exe
        for candidate in ["powershell.exe", "pwsh.exe", "cmd.exe"]:
            if shutil.which(candidate):
                logger.info("Configured shell '%s' not found, using '%s'", shell, candidate)
                return candidate

        logger.warning("No suitable shell found, defaulting to cmd.exe")
        return "cmd.exe"

    async def _winpty_read_loop(self):
        """Read loop for pywinpty ConPTY — works with both PtyProcess and legacy PTY."""
        loop = asyncio.get_event_loop()
        while self._running:
            try:
                # Keep exactly one blocking read in flight. Timing out an
                # executor future does not stop its worker thread; repeatedly
                # doing that creates abandoned readers which later consume and
                # discard pieces of PowerShell's cursor/redraw sequences.
                data = await loop.run_in_executor(None, self._conpty.read)
                if data:
                    if isinstance(data, bytes):
                        await self.ws.send_bytes(data)
                    else:
                        await self.ws.send_bytes(data.encode("utf-8", errors="replace"))
                elif not self._is_conpty_alive():
                    self._running = False
                    break
                else:
                    await asyncio.sleep(0.01)
            except asyncio.CancelledError:
                # cleanup() closes the PTY and releases the executor read.
                return
            except EOFError:
                # Process exited
                self._running = False
                break
            except Exception as e:
                if self._running:
                    logger.error("ConPTY read error for user '%s': %s", self.username, e)
                self._running = False
                break
        try:
            await self.ws.send_bytes(b"\r\n[Session ended]\r\n")
        except Exception:
            pass
        await self.cleanup()

    def _is_conpty_alive(self) -> bool:
        """Check if the ConPTY process is still alive."""
        try:
            if hasattr(self._conpty, 'is_alive'):
                return self._conpty.is_alive()
            if hasattr(self._conpty, 'isalive'):
                return self._conpty.isalive()
            if hasattr(self._conpty, 'pid') and self._conpty.pid:
                # Fallback: check if process exists
                import subprocess
                try:
                    os.kill(self._conpty.pid, 0)  # signal 0 = check existence
                    return True
                except (ProcessLookupError, OSError):
                    return False
        except Exception:
            return False
        return False

    async def _start_windows_fallback(self):
        """Subprocess pipe fallback when pywinpty is not available.

        This gives a basic terminal experience (command input/output)
        but does NOT support ANSI escape codes, interactive TUI apps,
        or tab completion. Install pywinpty for full support.
        """
        import subprocess

        shell = self._get_windows_shell()
        if shell.endswith("powershell.exe") or shell.endswith("pwsh.exe"):
            cmd = [shell, "-NoLogo", "-NoProfile", "-Command", "-"]
        else:
            cmd = [shell]

        self._process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,  # type: ignore
        )
        self.pid = self._process.pid
        self._running = True

        self._read_task = asyncio.create_task(self._windows_pipe_read_loop())
        _active_sessions.append(self)
        logger.info(
            "Terminal session started for user '%s' (pid=%d, subprocess fallback, sessions=%d)",
            self.username, self.pid, len(_active_sessions),
        )

    async def _windows_pipe_read_loop(self):
        loop = asyncio.get_event_loop()
        while self._running:
            try:
                line = await loop.run_in_executor(
                    None, self._process.stdout.readline
                )
                if line:
                    text = line.decode("utf-8", errors="replace")
                    await self.ws.send_bytes(text.encode("utf-8"))
                elif self._process.poll() is not None:
                    self._running = False
                    break
                else:
                    # No data yet, short sleep to avoid busy loop
                    await asyncio.sleep(0.05)
            except Exception as e:
                if self._running:
                    logger.error("Pipe read error: %s", e)
                self._running = False
                break
        try:
            await self.ws.send_bytes(b"\r\n[Session ended]\r\n")
        except Exception:
            pass
        await self.cleanup()

    # -----------------------------------------------------------------
    #  WRITE / RESIZE
    # -----------------------------------------------------------------
    async def write(self, data: bytes):
        if not self._running:
            return
        try:
            if IS_WINDOWS:
                if self._conpty is not None:
                    text = data.decode("utf-8", errors="replace")
                    if hasattr(self._conpty, 'write'):
                        self._conpty.write(text)
                elif self._process and self._process.stdin:
                    self._process.stdin.write(data)
                    self._process.stdin.flush()
            else:
                if self.fd is not None:
                    os.write(self.fd, data)
        except Exception as e:
            logger.warning("Terminal write failed for user '%s': %s", self.username, e)
            self._running = False

    async def resize(self, cols: int, rows: int):
        try:
            cols = max(2, min(int(cols), 1000))
            rows = max(1, min(int(rows), 500))
            self.cols = cols
            self.rows = rows
            if IS_WINDOWS:
                if self._conpty is not None:
                    if hasattr(self._conpty, 'setwinsize'):
                        # PtyProcess expects (rows, cols).
                        self._conpty.setwinsize(rows, cols)
                    elif hasattr(self._conpty, 'set_size'):
                        # The legacy PTY API expects (cols, rows).
                        self._conpty.set_size(cols, rows)
                    elif hasattr(self._conpty, 'resize'):
                        # Compatibility with PtyProcess variants that expose
                        # resize instead of setwinsize; they use (rows, cols).
                        self._conpty.resize(rows, cols)
            else:
                self._unix_set_pty_size(cols, rows)
        except Exception as e:
            logger.warning("Terminal resize failed: %s", e)

    # -----------------------------------------------------------------
    #  CLEANUP
    # -----------------------------------------------------------------
    async def cleanup(self):
        self._running = False
        if self._read_task and not self._read_task.done():
            self._read_task.cancel()

        if IS_WINDOWS:
            self._cleanup_windows()
        else:
            self._cleanup_unix()

        if self in _active_sessions:
            _active_sessions.remove(self)

        duration = ""
        if self._created_at:
            elapsed = time.monotonic() - self._created_at
            duration = f" (duration: {elapsed:.1f}s)"
        logger.info("Terminal session ended for user '%s'%s", self.username, duration)
        self.pid = None
        self.fd = None
        self._process = None
        self._conpty = None

    def _cleanup_unix(self):
        import signal
        if self.pid is not None:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.kill(self.pid, sig)
                except (ProcessLookupError, PermissionError):
                    pass
            try:
                os.waitpid(self.pid, 0)
            except ChildProcessError:
                pass
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass

    def _cleanup_windows(self):
        if self._conpty is not None:
            try:
                # PtyProcess.terminate() or PTY.kill() depending on API
                if hasattr(self._conpty, 'terminate'):
                    self._conpty.terminate(force=True)
                elif hasattr(self._conpty, 'kill'):
                    self._conpty.kill()
                elif hasattr(self._conpty, 'close'):
                    self._conpty.close()
            except Exception:
                pass
        if self._process is not None:
            try:
                self._process.kill()
            except Exception:
                pass
            try:
                self._process.wait(timeout=2)
            except Exception:
                pass
        if self.pid is not None:
            try:
                import signal
                os.kill(self.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass


async def cleanup_all_sessions():
    """Force-clean all active terminal sessions. Called on shutdown."""
    sessions = list(_active_sessions)
    logger.info("Cleaning up %d active terminal session(s)...", len(sessions))
    for session in sessions:
        await session.cleanup()
