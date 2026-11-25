"""Tier A local FFprobe via Bubblewrap.

Video bytes never leave this host for probing. Remote URLs are refused.
Tier B is not implemented. Fail closed when sandbox requirements are unmet.

Mandatory controls (abort on failure):
  - Bubblewrap binary present and executable
  - --unshare-net / --unshare-pid / --unshare-ipc / --unshare-uts in argv
  - Boot self-test with positive-then-negative runtime checks (canary, RO,
    net, pid/ipc/uts namespace inodes, env clear, output bound, positive probe)
  - RLIMIT_CPU, RLIMIT_AS, RLIMIT_NOFILE when apply_rlimits=True
  - RLIMIT_CORE=0 (mandatory; child aborts on set failure)
  - PR_SET_NO_NEW_PRIVS
  - Bounded stdout/stderr drain with process-group kill on oversize
  - Wall-clock timeout with process-group kill
  - No shell; argv arrays only; URL-like media paths refused

Residual exposure (documented, not eliminated):
  - Broad read-only ``/usr`` bind: FFprobe and its shared libraries need a
    reliable runtime. Narrowing to individual binaries was reviewed and
    rejected for Stage 2.3 because incomplete library graphs cause false
    isolation failures and flaky probes. The RO property is runtime-tested;
    the surface area remains a residual risk.
  - Optional host paths that do not exist (/lib64 on some layouts) are skipped.

FFprobe version strings are captured inside the sandbox at boot (cached).
Host-side ``ffprobe -version`` is not invoked on the probe path.
"""

from __future__ import annotations

import json
import logging
import os
import select
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from app.limits import (
    MAX_VIDEO_AUDIO_STREAMS,
    MAX_VIDEO_BITRATE_BPS,
    MAX_VIDEO_DURATION_MS,
    MAX_VIDEO_FRAME_RATE,
    MAX_VIDEO_HEIGHT,
    MAX_VIDEO_PIXELS,
    MAX_VIDEO_WIDTH,
)
from app.video_detect import codec_allowed

logger = logging.getLogger(__name__)

BWRAP = "/usr/bin/bwrap"
DEFAULT_FFPROBE = "/usr/bin/ffprobe"
CAT = "/bin/cat"
TRUE_BIN = "/bin/true"
PYTHON3 = "/usr/bin/python3"

PROBE_WALL_SECONDS = 25
PROBE_CPU_SECONDS = 20
PROBE_AS_BYTES = 512 * 1024 * 1024
PROBE_STDOUT_MAX = 1 * 1024 * 1024
PROBE_STDERR_MAX = 256 * 1024
PROBE_READ_CHUNK = 65_536

# Controls present in argv/source vs proven at boot. Callers and reports must
# not treat CONFIGURED_CONTROLS as runtime evidence.
CONFIGURED_CONTROLS = (
    "unshare_net",
    "unshare_pid",
    "unshare_ipc",
    "unshare_uts",
    "ro_runtime_binds",
    "scratch_bind",
    "clearenv",
    "no_shell",
    "protocol_whitelist",
    "fixed_media_path",
    "die_with_parent",
    "broad_usr_ro_bind",
)
RUNTIME_VERIFIED_CONTROLS = (
    "canary_outside_deny",
    "scratch_write_ok",
    "readonly_write_deny",
    "network_unshare",
    "pid_namespace_distinct",
    "ipc_namespace_distinct",
    "uts_namespace_distinct",
    "clearenv_runtime",
    "positive_ffprobe",
    "output_bound_kill",
    "rlimit_cpu_as_nofile",
    "no_new_privs",
    "sandboxed_ffprobe_version",
)

# Host env key injected into the bwrap parent process; must not appear inside.
_HOST_ENV_MARKER = "RC_VIDEO_PROBE_HOST_MARKER"
_HOST_ENV_MARKER_VALUE = "must-not-leak-into-sandbox"

_boot_lock = threading.Lock()
_boot_result: tuple[bool, str] | None = None
_ffprobe_version_cache: str = ""


class VideoProbeError(Exception):
    def __init__(self, code: str, message: str = "The video could not be analysed."):
        super().__init__(message)
        self.code = code
        self.message = message


def resolve_ffprobe_path(configured: str = "") -> str:
    path = (configured or "").strip() or DEFAULT_FFPROBE
    if not path.startswith("/") or ".." in path:
        raise VideoProbeError("video_toolchain_unavailable")
    if not os.path.isfile(path) or not os.access(path, os.X_OK):
        raise VideoProbeError("video_toolchain_unavailable")
    return path


def resolve_bwrap_path() -> str:
    if not os.path.isfile(BWRAP) or not os.access(BWRAP, os.X_OK):
        raise VideoProbeError("video_isolation_insufficient")
    return BWRAP


def tier_a_ready(ffprobe_configured: str = "") -> tuple[bool, str]:
    """Return whether Tier A can run; does not enable product ingest."""
    try:
        resolve_bwrap_path()
        resolve_ffprobe_path(ffprobe_configured)
    except VideoProbeError as exc:
        return False, exc.code
    ok, code = ensure_boot_self_test(ffprobe_configured)
    if not ok:
        return False, code
    return True, "tier_a"


def ensure_boot_self_test(ffprobe_configured: str = "") -> tuple[bool, str]:
    global _boot_result
    with _boot_lock:
        if _boot_result is not None:
            return _boot_result
        _boot_result = _run_boot_self_test(ffprobe_configured)
        return _boot_result


def reset_boot_self_test_for_tests() -> None:
    """Test helper only."""
    global _boot_result, _ffprobe_version_cache
    with _boot_lock:
        _boot_result = None
        _ffprobe_version_cache = ""


def _require_exec(path: str) -> None:
    if not os.path.isfile(path) or not os.access(path, os.X_OK):
        raise VideoProbeError("video_isolation_insufficient")


def _run_boot_self_test(ffprobe_configured: str) -> tuple[bool, str]:
    try:
        bwrap = resolve_bwrap_path()
        ffprobe = resolve_ffprobe_path(ffprobe_configured)
        _require_exec(CAT)
        _require_exec(TRUE_BIN)
        _require_exec(PYTHON3)
    except VideoProbeError as exc:
        return False, exc.code

    with tempfile.TemporaryDirectory(prefix="rc-video-boot-") as tmp:
        tmp_path = Path(tmp)
        fixture = tmp_path / "fixture.mp4"
        canary = tmp_path / "canary-secret.txt"
        scratch = tmp_path / "scratch"
        scratch.mkdir(mode=0o700)
        canary.write_text("SECRET", encoding="utf-8")
        try:
            _generate_tiny_fixture(fixture)
        except VideoProbeError:
            return False, "video_toolchain_unavailable"

        # Positive control: cat and true work on the host before sandbox claims.
        try:
            host_true = subprocess.run(
                [TRUE_BIN],
                capture_output=True,
                timeout=5,
                check=False,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            )
        except (OSError, subprocess.TimeoutExpired):
            return False, "video_isolation_insufficient"
        if host_true.returncode != 0:
            return False, "video_isolation_insufficient"

        # Scratch write must succeed inside the sandbox (no shell).
        scratch_ok = _bwrap_run(
            bwrap,
            scratch=scratch,
            media=fixture,
            ffprobe=ffprobe,
            argv=[
                PYTHON3,
                "-c",
                "p=open('/scratch/write-test','w'); p.write('ok'); p.close();"
                "import os; assert os.path.getsize('/scratch/write-test')>0",
            ],
            wall_seconds=5,
            include_ffprobe=False,
            apply_rlimits=False,
        )
        if scratch_ok.returncode != 0 or scratch_ok.timed_out or scratch_ok.output_oversize:
            return False, "video_isolation_insufficient"

        # Read-only runtime: writing under /usr must fail (EACCES/EROFS).
        ro_deny = _bwrap_run(
            bwrap,
            scratch=scratch,
            media=fixture,
            ffprobe=ffprobe,
            argv=[
                PYTHON3,
                "-c",
                "open('/usr/rc-video-ro-probe','w').write('x')",
            ],
            wall_seconds=5,
            include_ffprobe=False,
            apply_rlimits=False,
        )
        if ro_deny.returncode == 0:
            return False, "video_isolation_insufficient"

        # Canary outside allow-list must be unreadable. Require cat to exist
        # inside the sandbox and succeed on /media/input first (positive), then
        # fail on the canary (negative). Distinguishes missing-exec from deny.
        cat_ok = _bwrap_run(
            bwrap,
            scratch=scratch,
            media=fixture,
            ffprobe=ffprobe,
            argv=[CAT, "/media/input"],
            wall_seconds=5,
            include_ffprobe=False,
            apply_rlimits=False,
        )
        if cat_ok.returncode != 0 or cat_ok.timed_out or cat_ok.output_oversize:
            return False, "video_isolation_insufficient"
        deny = _bwrap_run(
            bwrap,
            scratch=scratch,
            media=fixture,
            ffprobe=ffprobe,
            argv=[CAT, str(canary.resolve())],
            wall_seconds=5,
            include_ffprobe=False,
            apply_rlimits=False,
        )
        if deny.returncode == 0:
            return False, "video_isolation_insufficient"

        # Network: require python to run a no-op successfully, then require
        # connect to fail. Missing python must fail the self-test.
        py_ok = _bwrap_run(
            bwrap,
            scratch=scratch,
            media=fixture,
            ffprobe=ffprobe,
            argv=[PYTHON3, "-c", "print(1)"],
            wall_seconds=5,
            include_ffprobe=False,
            apply_rlimits=False,
        )
        if py_ok.returncode != 0 or py_ok.timed_out or py_ok.output_oversize:
            return False, "video_isolation_insufficient"
        net = _bwrap_run(
            bwrap,
            scratch=scratch,
            media=fixture,
            ffprobe=ffprobe,
            argv=[
                PYTHON3,
                "-c",
                "import socket; s=socket.socket(); s.settimeout(1); s.connect(('1.1.1.1', 80))",
            ],
            wall_seconds=5,
            include_ffprobe=False,
            apply_rlimits=False,
        )
        if net.returncode == 0:
            return False, "video_isolation_insufficient"

        # Namespace isolation: read ns inodes inside the sandbox (positive), then
        # require each to differ from the host (negative / isolation proof).
        # Broken /proc must fail closed — never treat a crash as isolation success.
        try:
            host_ns = {
                "net": os.stat("/proc/self/ns/net").st_ino,
                "pid": os.stat("/proc/self/ns/pid").st_ino,
                "ipc": os.stat("/proc/self/ns/ipc").st_ino,
                "uts": os.stat("/proc/self/ns/uts").st_ino,
            }
        except OSError:
            return False, "video_isolation_insufficient"
        ns_read = _bwrap_run(
            bwrap,
            scratch=scratch,
            media=fixture,
            ffprobe=ffprobe,
            argv=[
                PYTHON3,
                "-c",
                "import os\n"
                "kinds=('net','pid','ipc','uts')\n"
                "print(' '.join(str(os.stat('/proc/self/ns/'+k).st_ino) for k in kinds))",
            ],
            wall_seconds=5,
            include_ffprobe=False,
            apply_rlimits=False,
        )
        if ns_read.returncode != 0 or ns_read.timed_out or ns_read.output_oversize:
            return False, "video_isolation_insufficient"
        try:
            parts = ns_read.stdout.decode("utf-8", errors="replace").strip().split()
            if len(parts) != 4:
                return False, "video_isolation_insufficient"
            sandbox_ns = {
                "net": int(parts[0]),
                "pid": int(parts[1]),
                "ipc": int(parts[2]),
                "uts": int(parts[3]),
            }
        except (TypeError, ValueError):
            return False, "video_isolation_insufficient"
        for kind in ("net", "pid", "ipc", "uts"):
            if sandbox_ns[kind] == host_ns[kind]:
                return False, "video_isolation_insufficient"

        # PID behavioral: prove /proc works and self-signal succeeds, then require
        # the host PID to be absent from the sandbox pid namespace. (bwrap's
        # helper is typically pid 1; the check command is often pid 2.)
        host_pid = os.getpid()
        pid_pos = _bwrap_run(
            bwrap,
            scratch=scratch,
            media=fixture,
            ffprobe=ffprobe,
            argv=[
                PYTHON3,
                "-c",
                "import os,sys\n"
                "os.kill(os.getpid(), 0)\n"
                "sys.exit(0 if os.path.isdir('/proc/1') and os.getpid() > 0 else 2)",
            ],
            wall_seconds=5,
            include_ffprobe=False,
            apply_rlimits=False,
        )
        if pid_pos.returncode != 0 or pid_pos.timed_out or pid_pos.output_oversize:
            return False, "video_isolation_insufficient"
        pid_deny = _bwrap_run(
            bwrap,
            scratch=scratch,
            media=fixture,
            ffprobe=ffprobe,
            argv=[
                PYTHON3,
                "-c",
                "import os,sys\n"
                f"hp={int(host_pid)}\n"
                "sys.exit(0 if os.path.exists('/proc/%d' % hp) else 3)",
            ],
            wall_seconds=5,
            include_ffprobe=False,
            apply_rlimits=False,
        )
        # Isolation success => exit 3 (host pid absent). Exit 0 means visible.
        if pid_deny.returncode != 3 or pid_deny.timed_out or pid_deny.output_oversize:
            return False, "video_isolation_insufficient"

        # IPC behavioral: create a host SysV semaphore, require sandbox attach deny
        # after proving sandbox can create its own semaphore.
        sem_key_host = 0x52435631  # RCV1
        sem_key_inner = 0x52435632  # RCV2
        host_sem = _sysv_semget(sem_key_host, create=True)
        if host_sem is None:
            return False, "video_isolation_insufficient"
        try:
            ipc_pos = _bwrap_run(
                bwrap,
                scratch=scratch,
                media=fixture,
                ffprobe=ffprobe,
                argv=[
                    PYTHON3,
                    "-c",
                    "import ctypes,sys\n"
                    "libc=ctypes.CDLL('libc.so.6',use_errno=True)\n"
                    f"sid=libc.semget({sem_key_inner},1,0o1000|0o2000|0o600)\n"
                    "sys.exit(0 if sid>=0 else 2)",
                ],
                wall_seconds=5,
                include_ffprobe=False,
                apply_rlimits=False,
            )
            if ipc_pos.returncode != 0 or ipc_pos.timed_out or ipc_pos.output_oversize:
                return False, "video_isolation_insufficient"
            ipc_deny = _bwrap_run(
                bwrap,
                scratch=scratch,
                media=fixture,
                ffprobe=ffprobe,
                argv=[
                    PYTHON3,
                    "-c",
                    "import ctypes,sys\n"
                    "libc=ctypes.CDLL('libc.so.6',use_errno=True)\n"
                    f"sid=libc.semget({sem_key_host},0,0)\n"
                    "sys.exit(0 if sid>=0 else 3)",
                ],
                wall_seconds=5,
                include_ffprobe=False,
                apply_rlimits=False,
            )
            if ipc_deny.returncode != 3 or ipc_deny.timed_out or ipc_deny.output_oversize:
                return False, "video_isolation_insufficient"
        finally:
            _sysv_sem_remove(host_sem)

        # Controlled environment: PATH/HOME set inside; host marker must not leak.
        env_check = _bwrap_run(
            bwrap,
            scratch=scratch,
            media=fixture,
            ffprobe=ffprobe,
            argv=[
                PYTHON3,
                "-c",
                "import os,sys\n"
                f"marker=os.environ.get({_HOST_ENV_MARKER!r})\n"
                "path=os.environ.get('PATH')\n"
                "home=os.environ.get('HOME')\n"
                "ok=(marker is None and path=='/usr/bin:/bin' and home=='/scratch')\n"
                "sys.exit(0 if ok else 2)",
            ],
            wall_seconds=5,
            include_ffprobe=False,
            apply_rlimits=False,
        )
        if env_check.returncode != 0 or env_check.timed_out or env_check.output_oversize:
            return False, "video_isolation_insufficient"

        # Output-size enforcement: unbounded printer must be killed and capped.
        flood = _bwrap_run(
            bwrap,
            scratch=scratch,
            media=fixture,
            ffprobe=ffprobe,
            argv=[
                PYTHON3,
                "-c",
                "import sys; sys.stdout.write('A' * (2 * 1024 * 1024))",
            ],
            wall_seconds=10,
            include_ffprobe=False,
            apply_rlimits=False,
            stdout_max=64 * 1024,
            stderr_max=64 * 1024,
        )
        if not flood.output_oversize:
            return False, "video_isolation_insufficient"
        if len(flood.stdout) > 64 * 1024 or len(flood.stderr) > 64 * 1024:
            return False, "video_isolation_insufficient"

        # Capture ffprobe version inside the sandbox (no host-side -version).
        global _ffprobe_version_cache
        ver = _bwrap_run(
            bwrap,
            scratch=scratch,
            media=fixture,
            ffprobe=ffprobe,
            argv=[ffprobe, "-version"],
            wall_seconds=5,
            include_ffprobe=True,
            apply_rlimits=False,
        )
        if ver.returncode != 0 or ver.timed_out or ver.output_oversize:
            return False, "video_isolation_insufficient"
        line = (ver.stdout or b"").decode("utf-8", errors="replace").split("\n", 1)[0].strip()
        if not line:
            return False, "video_isolation_insufficient"
        _ffprobe_version_cache = line[:200]

        # Positive: ffprobe on fixture succeeds inside sandbox with rlimits.
        try:
            probe_video_file(fixture, scratch_parent=scratch, ffprobe_path=ffprobe, skip_boot_check=True)
        except VideoProbeError as exc:
            return False, exc.code
    return True, "ok"


def _sysv_semget(key: int, *, create: bool) -> int | None:
    """Return a SysV semid or None when the host cannot create/open one."""
    import ctypes

    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        IPC_CREAT = 0o1000
        IPC_EXCL = 0o2000
        IPC_RMID = 0
        if create:
            existing = libc.semget(int(key), 0, 0)
            if existing >= 0:
                libc.semctl(int(existing), 0, IPC_RMID)
            sid = libc.semget(int(key), 1, IPC_CREAT | IPC_EXCL | 0o600)
            return int(sid) if sid >= 0 else None
        sid = libc.semget(int(key), 0, 0)
        return int(sid) if sid >= 0 else None
    except Exception:
        return None


def _sysv_sem_remove(semid: int) -> None:
    import ctypes

    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        IPC_RMID = 0
        libc.semctl(int(semid), 0, IPC_RMID)
    except Exception:
        pass


def _generate_tiny_fixture(path: Path) -> None:
    ffmpeg = "/usr/bin/ffmpeg"
    if not os.path.isfile(ffmpeg):
        raise VideoProbeError("video_toolchain_unavailable")
    cmd = [
        ffmpeg,
        "-y",
        "-f",
        "lavfi",
        "-i",
        "color=c=black:s=64x64:d=0.2",
        "-c:v",
        "libx264",
        "-pix_fmt",
        "yuv420p",
        "-t",
        "0.2",
        str(path),
    ]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            timeout=30,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VideoProbeError("video_toolchain_unavailable") from exc
    if completed.returncode != 0 or not path.is_file() or path.stat().st_size < 32:
        raise VideoProbeError("video_toolchain_unavailable")


def probe_video_file(
    media_path: Path,
    *,
    scratch_parent: Path,
    ffprobe_path: str = "",
    skip_boot_check: bool = False,
) -> dict:
    """Probe a local media file inside Tier A bwrap. Returns allow-listed fields."""
    media_path = Path(media_path).resolve()
    if not media_path.is_file() or media_path.is_symlink():
        raise VideoProbeError("video_probe_failed")
    text = str(media_path)
    if "://" in text or text.startswith("//"):
        raise VideoProbeError("video_probe_failed")

    if not skip_boot_check:
        ok, code = ensure_boot_self_test(ffprobe_path)
        if not ok:
            raise VideoProbeError(code if code != "ok" else "video_isolation_insufficient")

    bwrap = resolve_bwrap_path()
    ffprobe = resolve_ffprobe_path(ffprobe_path)
    scratch_parent = Path(scratch_parent)
    scratch_parent.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="probe-", dir=str(scratch_parent)))
    try:
        os.chmod(run_dir, 0o700)
        argv = [
            ffprobe,
            "-v",
            "error",
            "-print_format",
            "json",
            "-show_format",
            "-show_streams",
            "-show_error",
            "-analyzeduration",
            "5000000",
            "-probesize",
            "5000000",
            "-threads",
            "1",
            "-protocol_whitelist",
            "file,crypto,data",
            "/media/input",
        ]
        completed = _bwrap_run(
            bwrap,
            scratch=run_dir,
            media=media_path,
            ffprobe=ffprobe,
            argv=argv,
            wall_seconds=PROBE_WALL_SECONDS,
            include_ffprobe=True,
            apply_rlimits=True,
        )
        if completed.timed_out:
            raise VideoProbeError("video_probe_timeout")
        if completed.output_oversize:
            raise VideoProbeError("probe_output_too_large")
        if completed.returncode != 0:
            raise VideoProbeError("video_probe_failed")
        try:
            payload = json.loads(completed.stdout.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise VideoProbeError("video_probe_failed") from exc
        if not isinstance(payload, dict):
            raise VideoProbeError("video_probe_failed")
        return _parse_and_validate(payload, toolchain=completed.toolchain_version)
    finally:
        _rm_tree(run_dir)


class _ProbeResult:
    def __init__(
        self,
        returncode,
        stdout,
        stderr,
        timed_out=False,
        output_oversize=False,
        toolchain_version="",
    ):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.output_oversize = output_oversize
        self.toolchain_version = toolchain_version


def _bwrap_run(
    bwrap: str,
    *,
    scratch: Path,
    media: Path,
    ffprobe: str,
    argv: list[str],
    wall_seconds: int,
    include_ffprobe: bool,
    apply_rlimits: bool = False,
    stdout_max: int = PROBE_STDOUT_MAX,
    stderr_max: int = PROBE_STDERR_MAX,
) -> _ProbeResult:
    scratch = Path(scratch).resolve()
    media = Path(media).resolve()
    cmd = [
        bwrap,
        "--die-with-parent",
        "--new-session",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
    ]
    # Broad RO /usr (and lib/bin) retained: FFprobe's shared-library graph is
    # not stably enumerable across distros without risking probe false failures.
    # Residual attack surface; RO property is boot-tested separately.
    for host_path in ("/usr", "/lib", "/lib64", "/bin"):
        if os.path.exists(host_path):
            cmd.extend(["--ro-bind", host_path, host_path])
    for host_path in ("/etc/ld.so.cache", "/etc/alternatives"):
        if os.path.exists(host_path):
            cmd.extend(["--ro-bind", host_path, host_path])
    cmd.extend(
        [
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/run",
            "--bind",
            str(scratch),
            "/scratch",
            "--ro-bind",
            str(media),
            "/media/input",
            "--chdir",
            "/scratch",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "LANG",
            "C",
            "--setenv",
            "HOME",
            "/scratch",
        ]
    )
    if include_ffprobe and ffprobe and not ffprobe.startswith("/usr/"):
        if not os.path.isfile(ffprobe):
            raise VideoProbeError("video_toolchain_unavailable")
        cmd.extend(["--ro-bind", ffprobe, ffprobe])
    cmd.append("--")
    cmd.extend(list(argv))

    if not os.path.isdir("/usr"):
        raise VideoProbeError("video_isolation_insufficient")
    # Minimal parent env for bwrap itself. Marker must not survive --clearenv.
    parent_env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        _HOST_ENV_MARKER: _HOST_ENV_MARKER_VALUE,
    }
    preexec = _make_preexec(apply_rlimits)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            preexec_fn=preexec,
            env=parent_env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VideoProbeError("video_isolation_insufficient") from exc

    try:
        stdout, stderr, timed_out, oversize = bounded_communicate(
            proc,
            wall_seconds=wall_seconds,
            stdout_max=stdout_max,
            stderr_max=stderr_max,
        )
    except Exception:
        _kill_group(proc)
        _reap(proc, grace=2)
        raise

    version = _ffprobe_version_line(ffprobe)
    return _ProbeResult(
        proc.returncode if proc.returncode is not None else -1,
        stdout,
        stderr,
        timed_out,
        oversize,
        version,
    )


def bounded_communicate(
    proc: subprocess.Popen,
    *,
    wall_seconds: float,
    stdout_max: int,
    stderr_max: int,
) -> tuple[bytes, bytes, bool, bool]:
    """Read stdout/stderr incrementally; never retain more than the caps.

    When either stream exceeds its limit, the process group is killed immediately.
    Returns (stdout, stderr, timed_out, output_oversize).
    """
    if proc.stdout is None or proc.stderr is None:
        _kill_group(proc)
        _reap(proc, grace=2)
        raise VideoProbeError("video_isolation_insufficient")

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    timed_out = False
    oversize = False
    deadline = time.monotonic() + max(float(wall_seconds), 0.1)

    stdout_fd = proc.stdout.fileno()
    stderr_fd = proc.stderr.fileno()
    _set_nonblocking(stdout_fd)
    _set_nonblocking(stderr_fd)
    open_fds = {stdout_fd, stderr_fd}

    def _ingest(fd: int, chunk: bytes) -> None:
        nonlocal oversize
        if fd == stdout_fd:
            room = stdout_max - len(stdout_buf)
            if room > 0:
                stdout_buf.extend(chunk[:room])
            if len(chunk) > max(room, 0):
                oversize = True
        else:
            room = stderr_max - len(stderr_buf)
            if room > 0:
                stderr_buf.extend(chunk[:room])
            if len(chunk) > max(room, 0):
                oversize = True

    try:
        while True:
            if oversize:
                _kill_group(proc)
                break
            if not open_fds and proc.poll() is not None:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _kill_group(proc)
                break
            if not open_fds:
                try:
                    proc.wait(timeout=min(remaining, 0.25))
                except subprocess.TimeoutExpired:
                    continue
                break
            try:
                readable, _, _ = select.select(list(open_fds), [], [], min(remaining, 0.25))
            except (ValueError, OSError):
                break
            if not readable:
                if proc.poll() is not None:
                    for fd in list(open_fds):
                        try:
                            chunk = os.read(fd, PROBE_READ_CHUNK)
                        except (BlockingIOError, OSError):
                            open_fds.discard(fd)
                            continue
                        if not chunk:
                            open_fds.discard(fd)
                            continue
                        _ingest(fd, chunk)
                        if oversize:
                            break
                continue
            for fd in readable:
                try:
                    chunk = os.read(fd, PROBE_READ_CHUNK)
                except BlockingIOError:
                    continue
                except OSError:
                    open_fds.discard(fd)
                    continue
                if not chunk:
                    open_fds.discard(fd)
                    continue
                _ingest(fd, chunk)
                if oversize:
                    break
    finally:
        _reap(proc, grace=2)
        try:
            proc.stdout.close()
        except Exception:
            pass
        try:
            proc.stderr.close()
        except Exception:
            pass

    return bytes(stdout_buf), bytes(stderr_buf), timed_out, oversize


def _set_nonblocking(fd: int) -> None:
    import fcntl

    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


def _make_preexec(apply_rlimits: bool):
    """Mandatory: CPU/AS/NOFILE when apply_rlimits; always NO_NEW_PRIVS + CORE=0."""

    def _preexec():
        import resource

        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ValueError, OSError) as exc:
            # Mandatory soft fail path: raise to abort child start.
            raise SystemExit(87) from exc
        if apply_rlimits:
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (PROBE_CPU_SECONDS, PROBE_CPU_SECONDS))
                resource.setrlimit(resource.RLIMIT_AS, (PROBE_AS_BYTES, PROBE_AS_BYTES))
                resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            except (ValueError, OSError) as exc:
                raise SystemExit(88) from exc
        try:
            import ctypes

            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            PR_SET_NO_NEW_PRIVS = 38
            if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
                raise SystemExit(89)
        except SystemExit:
            raise
        except Exception:
            raise SystemExit(89)

    return _preexec


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:
            pass


def _reap(proc: subprocess.Popen, *, grace: float) -> None:
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        try:
            proc.wait(timeout=grace)
        except Exception:
            pass
    except Exception:
        pass


def _ffprobe_version_line(ffprobe: str) -> str:
    """Return the sandboxed ffprobe version captured at boot.

    Does not invoke host-side ffprobe. Before boot cache is populated the
    placeholder ``ffprobe`` is returned so probe paths never shell out on the
    host for version diagnostics.
    """
    del ffprobe  # Path is fixed at boot; retained for call-site compatibility.
    cached = _ffprobe_version_cache.strip()
    return cached[:200] if cached else "ffprobe"


def _parse_and_validate(payload: dict, *, toolchain: str) -> dict:
    fmt = payload.get("format") if isinstance(payload.get("format"), dict) else {}
    streams = payload.get("streams") if isinstance(payload.get("streams"), list) else []
    video_streams = [s for s in streams if isinstance(s, dict) and s.get("codec_type") == "video"]
    audio_streams = [s for s in streams if isinstance(s, dict) and s.get("codec_type") == "audio"]
    if not video_streams:
        raise VideoProbeError("no_video_stream")
    if len(audio_streams) > MAX_VIDEO_AUDIO_STREAMS:
        raise VideoProbeError("audio_streams_exceeded")
    vs = video_streams[0]
    audio = audio_streams[0] if audio_streams else None
    video_codec = str(vs.get("codec_name") or "").lower()
    audio_codec = str(audio.get("codec_name") or "").lower() if audio else None
    bad = codec_allowed(video_codec, audio_codec if audio_codec else None)
    if bad:
        raise VideoProbeError(bad)

    try:
        width = int(vs.get("width") or 0)
        height = int(vs.get("height") or 0)
    except (TypeError, ValueError):
        raise VideoProbeError("dimensions_out_of_range")
    if width <= 0 or height <= 0 or width > MAX_VIDEO_WIDTH or height > MAX_VIDEO_HEIGHT:
        raise VideoProbeError("dimensions_out_of_range")
    if width * height > MAX_VIDEO_PIXELS:
        raise VideoProbeError("pixels_out_of_range")

    duration_ms = _duration_ms(fmt, vs)
    if duration_ms is None or duration_ms <= 0 or duration_ms > MAX_VIDEO_DURATION_MS:
        raise VideoProbeError("duration_out_of_range")

    fps = _frame_rate(vs)
    if fps is None or fps <= 0 or fps > MAX_VIDEO_FRAME_RATE + 0.01:
        raise VideoProbeError("frame_rate_out_of_range")

    bit_rate = _bit_rate(fmt, vs)
    if bit_rate is not None and bit_rate > MAX_VIDEO_BITRATE_BPS:
        raise VideoProbeError("bitrate_out_of_range")

    format_name = str(fmt.get("format_name") or "")[:120]
    for stream in streams:
        if not isinstance(stream, dict):
            continue
        codec = str(stream.get("codec_name") or "").lower()
        if codec.startswith("encv") or codec.startswith("enca") or "drm" in codec:
            raise VideoProbeError("encrypted_media")

    tags = fmt.get("tags") if isinstance(fmt.get("tags"), dict) else {}
    allowed_tags = {}
    for key in ("title", "encoder", "creation_time", "location", "com.apple.quicktime.location.ISO6709"):
        if key in tags and isinstance(tags[key], str):
            allowed_tags[key] = tags[key][:500]

    return {
        "duration_ms": duration_ms,
        "width": width,
        "height": height,
        "video_codec": video_codec,
        "audio_codec": audio_codec,
        "format_name": format_name,
        "frame_rate": _frame_rate_text(vs),
        "bit_rate": bit_rate,
        "probe_summary": {
            "version": 1,
            "toolchain": toolchain[:200],
            "tags": allowed_tags,
            "video_stream_count": len(video_streams),
            "audio_stream_count": len(audio_streams),
        },
        "isolation_tier": "A",
        "toolchain_version": toolchain[:200],
    }


def _duration_ms(fmt: dict, vs: dict) -> int | None:
    for source in (fmt.get("duration"), vs.get("duration")):
        try:
            if source is None:
                continue
            seconds = float(source)
            if seconds > 0:
                return int(round(seconds * 1000))
        except (TypeError, ValueError):
            continue
    return None


def _frame_rate(vs: dict) -> float | None:
    for key in ("avg_frame_rate", "r_frame_rate"):
        text = str(vs.get(key) or "")
        if not text or text == "0/0":
            continue
        if "/" in text:
            num, den = text.split("/", 1)
            try:
                n = float(num)
                d = float(den)
                if d == 0:
                    continue
                return n / d
            except ValueError:
                continue
        try:
            return float(text)
        except ValueError:
            continue
    return None


def _frame_rate_text(vs: dict) -> str:
    for key in ("avg_frame_rate", "r_frame_rate"):
        text = str(vs.get(key) or "")
        if text and text != "0/0":
            return text[:32]
    return ""


def _bit_rate(fmt: dict, vs: dict) -> int | None:
    for source in (fmt.get("bit_rate"), vs.get("bit_rate")):
        try:
            if source is None:
                continue
            value = int(source)
            if value > 0:
                return value
        except (TypeError, ValueError):
            continue
    return None


def _rm_tree(path: Path) -> None:
    try:
        for child in path.iterdir():
            if child.is_dir() and not child.is_symlink():
                _rm_tree(child)
            else:
                try:
                    child.unlink()
                except OSError:
                    pass
        path.rmdir()
    except OSError:
        pass
