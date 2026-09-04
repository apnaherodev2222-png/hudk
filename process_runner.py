"""
process_runner.py
─────────────────────────────────────────────────────────────────────────
Native OS-subprocess script execution — replaces docker_runner.py.

WHY THIS EXISTS: Docker containers need to create their own network
bridge (docker0) via netlink, which requires the NET_ADMIN capability.
Some VPS/hosting environments (especially nested/sandboxed containers
sold as "VPS") don't grant that capability even to root, so `dockerd`
itself refuses to start there ("operation not permitted" creating the
bridge). This module runs scripts as plain subprocesses instead — no
Docker Engine required at all.

READ THIS — WHAT YOU LOSE COMPARED TO DOCKER (be honest with yourself
about this before relying on it for untrusted multi-tenant use):
  ✅ KEPT — per-script memory cap (RLIMIT_AS, same 256MB default)
  ✅ KEPT — per-script wall-clock timeout (RUN_TIMEOUT_SECONDS, unchanged)
  ✅ KEPT — fork-bomb protection (a watchdog kills the process group if
     it spawns more than PIDS_LIMIT descendants — see _pid_watchdog)
  ✅ KEPT — network access (you had ALLOW_NETWORK=True anyway, so this
     is not a behavior change)
  ❌ LOST — filesystem isolation. Docker only mounted the user's own
     folder inside the container; a script literally could not see
     anything else on the host. A subprocess runs as the SAME OS user
     as the bot itself (commonly root on these hosts), so a malicious
     script CAN read/write files anywhere that user can, not just its
     own folder.
  ❌ LOST — capability/privilege isolation (cap_drop=ALL, no-new-
     privileges). A subprocess has whatever privileges the bot process
     itself has.
  If you need real filesystem/process isolation without Docker's
  networking requirement, look into bubblewrap (bwrap) or firejail —
  both sandbox the filesystem via user namespaces, which (unlike
  Docker's bridge networking) does NOT need NET_ADMIN. run_script()
  below is the one place you'd wrap the launch command with either.
  This module does not do that today — script_scanner.py's pre-run
  static scanning and the human approval-bot review step are, for now,
  the only protection standing between an untrusted script and the
  host filesystem.
"""
import asyncio
import json
import logging
import os
import signal
import time
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger(__name__)

# ─── CONFIG (same numbers docker_runner.py used) ──────────────────────────
RUNTIMES = {
    'py': 'python3',
    'js': 'node',
}

MEM_LIMIT_BYTES = 256 * 1024 * 1024   # 256MB RAM cap per script (RLIMIT_AS)
PIDS_LIMIT = 64                        # fork-bomb guard (watchdog-enforced, see caveat below)
RUN_TIMEOUT_SECONDS = 6 * 60 * 60      # auto-kill a script after 6 hours (tune as needed)

_WATCHDOG_INTERVAL = 5  # seconds between fork-bomb / memory watchdog checks

BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = BASE_DIR / 'inf' / 'process_runner_state.json'
STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

# In-memory registry for THIS process's own lifetime: pid -> {"popen": Popen, "log_file": handle}
# Only used to get exact exit codes for runs started in the current bot
# session — after a restart we fall back to "still running or not" via
# psutil, since a bare PID can't tell you its own exit code once it's gone.
_live = {}


# ─── state persistence (so a bot restart can reconnect to still-running scripts) ──
def _load_state() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_state(state: dict):
    try:
        STATE_FILE.write_text(json.dumps(state))
    except OSError as e:
        logger.error(f"Could not persist process_runner state: {e}")


def _state_put(pid: int, script_key: str, log_path: str, create_time: float):
    state = _load_state()
    state[str(pid)] = {
        'script_key': script_key,
        'log_path': log_path,
        'create_time': create_time,
    }
    _save_state(state)


def _state_pop(pid: int):
    state = _load_state()
    state.pop(str(pid), None)
    _save_state(state)


def _resource_limits_preexec():
    """Runs in the CHILD process right after fork(), before exec(). Sets
    the memory ceiling and detaches into its own session so the whole
    process GROUP (the script + anything it spawns) can be killed
    together via os.killpg — matches Docker's "killing the container
    kills everything inside it" behavior.

    NOTE ON RLIMIT_NPROC: we deliberately do NOT set RLIMIT_NPROC here.
    That limit is per real-user-ID system-wide, not per-process-tree —
    if the bot runs as root and every hosted script also runs as root
    (the common case on these VPS setups), a single shared NPROC cap
    would silently count every user's scripts AND the bot itself
    against the same budget, breaking everything as soon as 2-3 users
    ran something concurrently. Fork-bomb protection is instead handled
    by _pid_watchdog() below, which counts each script's own process
    tree individually via psutil."""
    os.setsid()
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT_BYTES, MEM_LIMIT_BYTES))
    except (ValueError, OSError):
        pass  # some hosts don't allow lowering this — degrade gracefully rather than failing the run


async def _pid_watchdog(pid: int, script_key: str):
    """Background task: kills the process group if it spawns more than
    PIDS_LIMIT descendants (fork-bomb guard) or if RSS memory creeps
    past the limit despite RLIMIT_AS (a second line of defense — some
    interpreters allocate lazily / RLIMIT_AS can be imprecise for them)."""
    if psutil is None:
        return
    while True:
        await asyncio.sleep(_WATCHDOG_INTERVAL)
        try:
            proc = psutil.Process(pid)
            if not proc.is_running():
                return
            descendants = proc.children(recursive=True)
            if len(descendants) + 1 > PIDS_LIMIT:
                logger.warning(f"{script_key}: process count {len(descendants)+1} exceeded limit, killing.")
                _kill_group(pid)
                return
            total_rss = proc.memory_info().rss + sum(
                (c.memory_info().rss for c in descendants if c.is_running()), 0
            )
            if total_rss > MEM_LIMIT_BYTES * 1.5:  # 50% headroom over RLIMIT_AS before the watchdog steps in
                logger.warning(f"{script_key}: memory {total_rss/1024/1024:.0f}MB exceeded limit, killing.")
                _kill_group(pid)
                return
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return


def _kill_group(pid: int, timeout: int = 5):
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    if psutil is not None:
        try:
            psutil.Process(pid).wait(timeout=timeout)
            return
        except (psutil.NoSuchProcess, psutil.TimeoutExpired, psutil.AccessDenied):
            pass
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


class ProcessRunner:
    def __init__(self):
        self.available = psutil is not None

    def is_available(self) -> bool:
        return self.available

    def ensure_images(self):
        """Docker equivalent pulled images; there's nothing to pull here —
        just check the interpreters we need are actually installed, so a
        missing `node`/`python3` shows up in logs at startup instead of
        as a confusing per-user failure later."""
        import shutil as _shutil
        for lang, binary in RUNTIMES.items():
            if _shutil.which(binary) is None:
                logger.warning(f"'{binary}' not found on PATH — .{lang} scripts will fail to run.")

    def run_script(self, file_path: Path, file_ext: str, user_folder: Path, script_key: str, env: dict = None):
        """Starts a subprocess running the given script. Returns
        (pid_as_str_or_None, error_message_or_None) — mirrors
        docker_runner.py's (container_id, error) shape exactly."""
        if not self.is_available():
            return None, "psutil is not installed — required for the sandbox. Run: pip install psutil"

        lang = file_ext.lstrip('.')
        interpreter = RUNTIMES.get(lang)
        if interpreter is None:
            return None, f"No runtime configured for .{lang} files."

        try:
            rel_path = file_path.resolve().relative_to(user_folder.resolve())
        except ValueError:
            rel_path = Path(file_path.name)
        rel_path_str = str(rel_path).replace('\\', '/')
        entry_dir = str(rel_path.parent).replace('\\', '/')
        entry_dir = '' if entry_dir in ('.', '') else entry_dir + '/'

        if lang == 'py':
            cmd = (
                f'if [ -f "{entry_dir}requirements.txt" ]; then '
                f'  echo "📦 Installing requirements..."; '
                f'  pip install -r "{entry_dir}requirements.txt" -q --no-cache-dir --break-system-packages 2>/dev/null '
                f'    || pip install -r "{entry_dir}requirements.txt" -q --no-cache-dir; '
                f'  echo "✅ Requirements installed"; '
                f'elif [ -f "requirements.txt" ]; then '
                f'  echo "📦 Installing requirements..."; '
                f'  pip install -r "requirements.txt" -q --no-cache-dir --break-system-packages 2>/dev/null '
                f'    || pip install -r "requirements.txt" -q --no-cache-dir; '
                f'  echo "✅ Requirements installed"; '
                f'fi; '
                f'python3 "{rel_path_str}"'
            )
        else:  # js
            cmd = (
                f'if [ -f "{entry_dir}package.json" ]; then '
                f'  echo "📦 Installing npm packages..."; '
                f'  npm install --prefix "{entry_dir or "."}" --quiet; '
                f'  echo "✅ Packages installed"; '
                f'fi; '
                f'node "{rel_path_str}"'
            )

        log_path = user_folder / f"{Path(rel_path.name).stem}.log"

        try:
            log_file = open(log_path, 'wb', buffering=0)
        except OSError as e:
            return None, f"Could not open log file: {e}"

        run_env = dict(os.environ)
        if env:
            run_env.update({str(k): str(v) for k, v in env.items()})

        try:
            import subprocess
            proc = subprocess.Popen(
                ['bash', '-c', cmd],
                cwd=str(user_folder.resolve()),
                stdout=log_file,
                stderr=subprocess.STDOUT,
                env=run_env,
                preexec_fn=_resource_limits_preexec,
                close_fds=True,
            )
        except OSError as e:
            log_file.close()
            return None, f"Failed to start process: {e}"

        pid = proc.pid
        _live[pid] = {'popen': proc, 'log_file': log_file}
        try:
            create_time = psutil.Process(pid).create_time() if psutil else time.time()
        except Exception:
            create_time = time.time()
        _state_put(pid, script_key, str(log_path), create_time)

        try:
            loop = asyncio.get_event_loop()
            loop.create_task(_pid_watchdog(pid, script_key))
        except RuntimeError:
            pass  # no running loop (shouldn't happen when called from the bot) — watchdog just won't run this session

        return str(pid), None

    def stop_script(self, container_id: str, timeout: int = 5) -> bool:
        try:
            pid = int(container_id)
        except (TypeError, ValueError):
            return False
        _kill_group(pid, timeout=timeout)
        live = _live.pop(pid, None)
        if live is not None:
            try:
                live['log_file'].close()
            except OSError:
                pass
        _state_pop(pid)
        return True

    def _verify(self, pid: int) -> bool:
        """True if this PID is still alive AND is (almost certainly) the
        same process we started — guards against a PID being recycled by
        the OS for an unrelated process after ours exited."""
        if psutil is None or not psutil.pid_exists(pid):
            return False
        state = _load_state().get(str(pid))
        if state is None:
            return False
        try:
            actual_create_time = psutil.Process(pid).create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
        return abs(actual_create_time - state['create_time']) < 2.0

    def is_running(self, container_id: str) -> bool:
        try:
            pid = int(container_id)
        except (TypeError, ValueError):
            return False
        if not self._verify(pid):
            return False
        try:
            return psutil.Process(pid).is_running()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def get_exit_code(self, container_id: str):
        try:
            pid = int(container_id)
        except (TypeError, ValueError):
            return None
        live = _live.get(pid)
        if live is not None:
            return live['popen'].poll()
        return None  # recovered-after-restart processes: exit code isn't retrievable, only alive/not

    def get_stats(self, container_id: str):
        try:
            pid = int(container_id)
        except (TypeError, ValueError):
            return None
        if psutil is None or not self._verify(pid):
            return None
        try:
            proc = psutil.Process(pid)
            if not proc.is_running():
                return None
            cpu_percent = proc.cpu_percent(interval=0.1)
            descendants = proc.children(recursive=True)
            mem_used = proc.memory_info().rss + sum(
                (c.memory_info().rss for c in descendants if c.is_running()), 0
            )
            mem_used_mb = mem_used / (1024 * 1024)
            mem_limit_mb = MEM_LIMIT_BYTES / (1024 * 1024)
            mem_percent = (mem_used / MEM_LIMIT_BYTES) * 100.0
            return {
                'cpu_percent': round(cpu_percent, 1),
                'mem_used_mb': round(mem_used_mb, 1),
                'mem_limit_mb': round(mem_limit_mb, 1),
                'mem_percent': round(mem_percent, 1),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def get_logs(self, container_id: str, tail: int = 500) -> str:
        try:
            pid = int(container_id)
        except (TypeError, ValueError):
            return "(invalid process id)"
        state = _load_state().get(str(pid))
        if state is None:
            return "(process no longer exists — it may have been stopped/cleaned up)"
        log_path = Path(state['log_path'])
        if not log_path.exists():
            return "(log file not found)"
        try:
            lines = log_path.read_text(encoding='utf-8', errors='replace').splitlines()
            return "\n".join(lines[-tail:])
        except OSError as e:
            return f"(error reading logs: {e})"

    def list_managed_containers(self):
        """Reconciliation source — reads our own state file (the JSON
        equivalent of Docker's `docker ps --filter label=...`) instead of
        asking an external daemon, since there isn't one anymore."""
        state = _load_state()
        results = []
        for pid_str, info in state.items():
            pid = int(pid_str)
            alive = self._verify(pid)
            results.append({
                'container_id': pid_str,
                'script_key': info['script_key'],
                'status': 'running' if alive else 'exited',
            })
        return results

    def cleanup_finished(self):
        """Prunes dead entries out of the state file — the JSON
        equivalent of removing exited containers so it doesn't pile up."""
        state = _load_state()
        changed = False
        for pid_str in list(state.keys()):
            if not self._verify(int(pid_str)):
                state.pop(pid_str, None)
                changed = True
                live = _live.pop(int(pid_str), None)
                if live is not None:
                    try:
                        live['log_file'].close()
                    except OSError:
                        pass
        if changed:
            _save_state(state)


docker_runner = ProcessRunner()  # kept as `docker_runner` so hosting_panel.py's
                                  # existing 27 call sites need zero changes —
                                  # it's just an adapter object now, not Docker.


async def watch_timeout(container_id: str, timeout_seconds: int, on_timeout):
    """Background asyncio task: force-kills a process if it's still
    running after timeout_seconds. `on_timeout` is an awaitable callback
    (no args) you use to update bot_scripts / notify the user."""
    await asyncio.sleep(timeout_seconds)
    if docker_runner.is_running(container_id):
        docker_runner.stop_script(container_id)
        try:
            await on_timeout()
        except Exception as e:
            logger.error(f"on_timeout callback failed: {e}")
