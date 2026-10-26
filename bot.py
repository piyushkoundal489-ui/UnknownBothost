"""
╔══════════════════════════════════════════════════════╗
║        UnknownXHosting — New Era Bot  v2.0           ║
║        Owner    : @UnknownNvrDie                     ║
║        Owner ID : 7642584056                         ║
║        File     : Unknownxhost.py                    ║
╚══════════════════════════════════════════════════════╝

Security Features:
  • All bot tokens encrypted at rest with Fernet
  • Per-action rate limiter + global anti-flood
  • File security scanner blocks dangerous code on upload
  • Subprocess isolation: hosted bots cannot read host secrets
  • Fernet key stored chmod 600 (owner read-only)

Requirements:
    pip install python-telegram-bot==22.7 flask psutil requests cryptography

Run:
    python Unknownxhost.py
    or:  BOT_TOKEN=xxx python Unknownxhost.py
"""

from __future__ import annotations

import html
import os
import re
import uuid
import json
import shutil
import zipfile
import hashlib
import random
import string
import signal
import logging
import traceback
import stat
import threading
import subprocess
import time
import shlex
import sys
import asyncio
import resource
import pwd
import socket
import urllib.request as _urlreq
import urllib.parse   as _urlparse
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO

try:
    import psutil as _psutil
    _PSUTIL = True
except ImportError as _psutil_err:
    _PSUTIL = False
    print(f"[STARTUP WARNING] psutil not importable — RAM display and RAM "
          f"auto-kill enforcement are BOTH disabled until this is fixed: {_psutil_err}")

try:
    from cryptography.fernet import Fernet
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, CallbackQuery
from telegram.error import BadRequest, NetworkError, TimedOut, Forbidden, RetryAfter
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
from telegram.constants import ParseMode

# ==========================================
# Smooth Button Transitions
# ==========================================
# Telegram's Bot API has no fade/cross-dissolve primitive for edited
# messages — that part is 100% controlled by the Telegram client, not the
# bot. What we CAN do is stop the new content from landing in the exact
# same instant as the tap, so the client's own tap-ripple/highlight
# animation has time to finish before the message body changes. This is
# patched once here (instead of touching all 371 individual button
# handlers) because nearly every handler calls CallbackQuery.edit_message_text
# under the hood via `q.edit_message_text(...)`.
_SMOOTH_TRANSITION_DELAY = 0.15  # seconds — tweak to taste

_ORIG_CQ_EDIT_MESSAGE_TEXT = CallbackQuery.edit_message_text

async def _smooth_cq_edit_message_text(self, *args, **kwargs):
    await asyncio.sleep(_SMOOTH_TRANSITION_DELAY)
    return await _ORIG_CQ_EDIT_MESSAGE_TEXT(self, *args, **kwargs)

CallbackQuery.edit_message_text = _smooth_cq_edit_message_text

#  Prevents Replit from killing the process due
#  to inactivity. Also used by UptimeRobot pings.
try:
    from flask import Flask as _Flask
    from threading import Thread as _Thread

    _flask_app = _Flask("keep_alive")

    @_flask_app.route("/")
    def _home():
        return "✅ UnknownXHost Bot is alive and running!"

    @_flask_app.route("/health")
    def _health():
        return {"status": "ok", "bot": "UnknownXHosting v2.0"}, 200

    def _run_flask():
        import os as _os
        port = int(_os.environ.get("PORT", 8000))
        import logging as _logging
        _logging.getLogger("werkzeug").setLevel(_logging.ERROR)
        _flask_app.run(host="0.0.0.0", port=port, use_reloader=False, threaded=True)

    def keep_alive():
        t = _Thread(target=_run_flask, daemon=True)
        t.start()
        print(f"[KEEP-ALIVE] Flask keep-alive server started on port {os.environ.get('PORT', 8000)}.")

    _KEEP_ALIVE_AVAILABLE = True
except ImportError:
    def keep_alive():
        print("[KEEP-ALIVE] flask not installed — keep-alive disabled. Run: pip install flask")
    _KEEP_ALIVE_AVAILABLE = False


Bot_token = os.environ.get("BOT_TOKEN", "").strip()
if not Bot_token:
    sys.exit(
        "[STARTUP ERROR] BOT_TOKEN environment variable is not set.\n"
        "Set it before starting the bot, e.g.:\n"
        "    BOT_TOKEN=123456:ABC-your-token python Unknownxhost.py\n"
        "This host bot's own token must never be hardcoded in source — "
        "anyone with the file (or the repo/git history) would get full control of the bot."
    )


OWNER_ID   = 7642584056
ADMIN_IDS  = [OWNER_ID]
DEVELOPER_USERNAME = "UnknownNvrDie"

CLOUD_STORAGE_CHAT_ID = -1003909692553
CLOUD_STORAGE_TAG     = "#BOT_STORAGE"       # prefix on every storage message
CLOUD_BACKUP_TAG      = "#BOT_STORAGE_BACKUP"  # prefix on backup messages

HARDCODED_FJ_CHANNELS = [
    {"title": "Updates & Codes", "username": "@UnknownXBotUpdateAndCodes", "link": "https://t.me/UnknownXBotUpdateAndCodes"},
    {"title": "Bots Hub",        "username": "@UnknownXBotsHub",            "link": "https://t.me/UnknownXBotsHub"},
]
BASE_DIR          = os.path.dirname(os.path.abspath(__file__))
DB_PATH           = os.path.join(BASE_DIR, "hosting_data.json")
BOTS_DIR          = os.path.join(BASE_DIR, "bots")
HOSTED_FILES_DIR      = os.path.join(BASE_DIR, "hosted_files")        # uploaded bot files (shown to users)
BOT_DATA_DIR          = os.path.join(BASE_DIR, "bot_data")            # runtime working dirs (data files created by bots)
HOSTED_BOT_USERS_DIR  = os.path.join(BASE_DIR, "hosted_bot_users")    # per-bot user lists (separate from hosting-bot users)
BACKUP_DIR        = os.path.join(BASE_DIR, "backup")
LOGS_DIR          = os.path.join(BASE_DIR, "bot_logs")
MAX_BYTES  = 25 * 1024 * 1024    # 25 MB
LOG_LINES  = 60
ALLOWED_EXTENSIONS = {".py"}
START_TIME = datetime.now(timezone.utc)


def _setup_security_logger() -> logging.Logger:
    sec_logger = logging.getLogger("hosting_security")
    sec_logger.setLevel(logging.INFO)
    if sec_logger.handlers:
        return sec_logger
    formatter = logging.Formatter(
        "%(asctime)s [SECURITY] %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bot_logs")
    os.makedirs(log_dir, exist_ok=True)
    fh = logging.FileHandler(os.path.join(log_dir, "security_audit.log"), encoding="utf-8")
    fh.setFormatter(formatter)
    sec_logger.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    sec_logger.addHandler(sh)
    sec_logger.propagate = False
    return sec_logger

_SECLOG = _setup_security_logger()

def _sec_event(event_type: str, detail: str, user_id: int | None = None,
               filename: str | None = None) -> None:
    """Emit a structured security audit log entry."""
    parts = [f"event={event_type}"]
    if user_id is not None:
        parts.append(f"user={user_id}")
    if filename:
        parts.append(f"file={filename!r}")
    parts.append(f"detail={detail!r}")
    _SECLOG.warning(" | ".join(parts))

_IST = timezone(timedelta(hours=5, minutes=30))

def _now_ist() -> datetime:
    return datetime.now(_IST)

def _now() -> str:
    return _now_ist().isoformat()

def _parse_dt(iso_str: str) -> datetime:
    """
    Parse an ISO datetime string.
    - New entries: timezone-aware IST strings → returned as-is.
    - Short date strings like "15-04-2027" → parsed as IST midnight.
    - Old entries: naive UTC strings → treated as UTC, converted to IST.
    Always returns a timezone-aware datetime in IST for consistent comparison.
    """
    if iso_str and re.match(r"^\d{2}-\d{2}-\d{4}$", iso_str):
        dt = datetime.strptime(iso_str, "%d-%m-%Y").replace(tzinfo=_IST)
        return dt
    dt = datetime.fromisoformat(iso_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc).astimezone(_IST)
    return dt
PIP_INSTALL_TIMEOUT = 180

PIP_TARGET_DIR = os.path.join(BASE_DIR, "pip_packages")
os.makedirs(PIP_TARGET_DIR, exist_ok=True)

# Plans — lifetime has file_limit=-1 / ram_mb=-1 meaning truly unlimited.
# ram_mb is the per-bot RAM ceiling (MB) enforced by the RAM watchdog (see
# _ram_enforcer_loop): a bot whose live RSS exceeds its owner's plan limit
# gets auto-stopped and the owner is notified.
PLANS = {
    "free":      {"name": "Free",              "emoji": "🆓", "file_limit": 2,   "run_limit": 2,   "ram_mb": 312,  "price": "Free",    "needs_approval": True},
    "baby":      {"name": "Baby",              "emoji": "🍼", "file_limit": 5,   "run_limit": 5,   "ram_mb": 512,  "price": "₹69",     "needs_approval": False},
    "basic":     {"name": "Basic",             "emoji": "⭐", "file_limit": 10,  "run_limit": 10,  "ram_mb": 1024, "price": "₹99",     "needs_approval": False},
    "premium":   {"name": "Premium",           "emoji": "💎", "file_limit": 25,  "run_limit": 25,  "ram_mb": 2048, "price": "₹199",    "needs_approval": False},
    "god":       {"name": "God",               "emoji": "⚡", "file_limit": 150, "run_limit": 150, "ram_mb": 4096, "price": "₹499",    "needs_approval": False},
    "ultimate":  {"name": "Ultimate",          "emoji": "👑", "file_limit": 999, "run_limit": 999, "ram_mb": 8192, "price": "₹999",    "needs_approval": False},
    "lifetime":  {"name": "Unlimited Lifetime","emoji": "♾️", "file_limit": -1,  "run_limit": -1,  "ram_mb": -1,   "price": "₹1500",   "needs_approval": False},
}

UNLIMITED_SENTINEL = -1

os.makedirs(BOTS_DIR,             exist_ok=True)
os.makedirs(HOSTED_FILES_DIR,     exist_ok=True)
os.makedirs(BOT_DATA_DIR,         exist_ok=True)
os.makedirs(BACKUP_DIR,           exist_ok=True)
os.makedirs(LOGS_DIR,             exist_ok=True)
os.makedirs(HOSTED_BOT_USERS_DIR, exist_ok=True)

#  SANDBOX / CONTAINER SECURITY CONFIG

# Max RAM per hosted bot process (256 MB)
_BOT_MAX_RAM_BYTES = 256 * 1024 * 1024
# Max CPU time per bot process (seconds, hard limit)
_BOT_MAX_CPU_SECS  = 3600
# Whether bubblewrap (bwrap) is available for full namespace isolation
_BWRAP_PATH = shutil.which("bwrap")
# Whether firejail is available as an alternative sandbox
_FIREJAIL_PATH = shutil.which("firejail")

# Directories that hosted bots must NEVER be able to reach
_BLOCKED_PATHS = ["/root", "/home", "/etc/shadow", "/etc/passwd"]

# ── Host-process resource ceiling ──────────────────────────────────────
# Every running hosted bot costs the HOST process (this script, not the
# sandboxed child) roughly:
#   • 1 OS process   (the subprocess.Popen'd bot)
#   • 1 open file    (the shared stdout/stderr log file handle)
#   • 1 OS thread    (its dedicated watchdog thread)
# At 300-400 concurrently running bots that adds up fast, and most Linux/
# Termux environments default to a soft RLIMIT_NOFILE of ~1024 and a
# fairly low RLIMIT_NPROC, which silently caps how many bots can actually
# stay running. This raises this process's own limits (not the sandboxed
# per-bot limits set in _sandbox_preexec, which are untouched) up to
# whatever the hard ceiling allows, so 300-400 concurrent bots is
# actually reachable instead of failing partway with "Too many open
# files" / "Resource temporarily unavailable".
_HOST_TARGET_NOFILE = 65536
_HOST_TARGET_NPROC  = 16384

def _raise_host_rlimits() -> None:
    for res, target, label in (
        (resource.RLIMIT_NOFILE, _HOST_TARGET_NOFILE, "RLIMIT_NOFILE"),
        (resource.RLIMIT_NPROC,  _HOST_TARGET_NPROC,  "RLIMIT_NPROC"),
    ):
        try:
            soft, hard = resource.getrlimit(res)
            ceiling = hard if hard != resource.RLIM_INFINITY else target
            new_soft = min(target, ceiling)
            if new_soft > soft:
                resource.setrlimit(res, (new_soft, hard))
                print(f"[LIMITS] {label} raised: {soft} → {new_soft} (hard={hard})")
            else:
                print(f"[LIMITS] {label} already {soft} (hard={hard}), no change made")
        except Exception as e:
            print(f"[LIMITS] Could not raise {label}: {e}")

_DECOY_MSG = "𝘽𝙚𝙝𝙖𝙣 𝙠𝙚 𝙡𝙤𝙙𝙚 𝙈𝙠𝙘 𝙏𝙚𝙧𝙞 𝙡𝙚 𝙡𝙤𝙙𝙖 𝙡𝙚𝙡𝙚 🍌🖕\n"
# Sub-directory created inside each bot's working dir to hold the injected
# sitecustomize.py that enforces filesystem confinement at the Python level.
_SANDBOX_INJECT_SUBDIR = ".sandbox_inject"

def _sandbox_preexec(bot_dir: str):
    try:
        os.setsid()
        # NOTE: RLIMIT_AS (virtual address space) is intentionally NOT set here.
        # Python uses 500 MB–1 GB+ of *virtual* address space on 64-bit systems
        # even for small scripts (shared library mmaps, etc.).  Capping AS at
        # 256 MB causes bots to crash during import of large packages such as
        # python-telegram-bot / asyncio, which makes bots show as "Running" but
        # immediately die after the startup liveness check.
        # CPU time limit
        try:
            resource.setrlimit(resource.RLIMIT_CPU,
                               (_BOT_MAX_CPU_SECS, _BOT_MAX_CPU_SECS))
        except Exception:
            pass
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
        except Exception:
            pass
        try:
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        except Exception:
            pass
    except Exception:
        pass  # Never crash the child — it will exec regardless

def _build_sandbox_cmd(cmd: list, bot_dir: str, script_path: str = "") -> list:
    """
    Wrap `cmd` in a bubblewrap or firejail sandbox if available.
    Falls back to the plain command with preexec limits only.

    script_path: the single bot script file (.py) being launched.  It lives in
    HOSTED_FILES_DIR which is intentionally NOT fully mounted — only this one
    file is exposed (read-only) so Python can exec it without exposing sibling
    bot files, the hosting DB, or the Fernet key.
    """
    if _BWRAP_PATH:
        # bubblewrap: full user-namespace container.
        #
        # Filesystem model (most-restrictive-wins):
        #   • Only the Python runtime (/usr, /lib, /lib64, /bin, /sbin) is
        #     read-only mounted — nothing else from the host is visible.
        #   • bot_dir is the ONLY writable location (the bot's isolated workspace).
        #   • script_path is mounted read-only as a single file so Python can
        #     exec it; the rest of HOSTED_FILES_DIR is not mounted at all.
        #   • PIP_TARGET_DIR is mounted read-only so auto-installed packages work.
        #   • /home and /root are overlaid with empty tmpfs so even if paths
        #     exist on the host they appear empty inside the sandbox.
        #   • /tmp is a fresh tmpfs; /proc is a private proc; /dev is minimal.
        #   • Network is kept open (Telegram bots need api.telegram.org) but the
        #     bots' dirs, /etc/shadow, /etc/sudoers — is simply not mounted.
        #
        sandbox_cmd = [
            _BWRAP_PATH,
            "--ro-bind",     "/usr", "/usr",
            "--ro-bind-try", "/lib",   "/lib",
            "--ro-bind-try", "/lib64", "/lib64",
            "--ro-bind-try", "/bin",   "/bin",
            "--ro-bind-try", "/sbin",  "/sbin",
            "--ro-bind-try", "/etc/resolv.conf",   "/etc/resolv.conf",
            "--ro-bind-try", "/etc/ssl",            "/etc/ssl",
            "--ro-bind-try", "/etc/hosts",          "/etc/hosts",
            "--ro-bind-try", "/etc/nsswitch.conf",  "/etc/nsswitch.conf",
            "--ro-bind-try", "/etc/localtime",      "/etc/localtime",
            "--ro-bind-try", "/etc/timezone",       "/etc/timezone",
            "--bind", bot_dir, bot_dir,
        ]
        if script_path and os.path.isfile(script_path):
            sandbox_cmd += ["--ro-bind", script_path, script_path]
        if os.path.isdir(PIP_TARGET_DIR):
            sandbox_cmd += ["--ro-bind", PIP_TARGET_DIR, PIP_TARGET_DIR]
        sandbox_cmd += [
            "--tmpfs", "/tmp",
            "--proc", "/proc",
            "--dev",  "/dev",
            "--dir",   "/home",
            "--tmpfs", "/home",
            "--dir",   "/root",
            "--tmpfs", "/root",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
            "--setenv", "HOME",   bot_dir,  # prevent ~/... escapes
            "--setenv", "TMPDIR", "/tmp",
            "--",
        ] + cmd
        return sandbox_cmd
    if _FIREJAIL_PATH:
        sandbox_cmd = [
            _FIREJAIL_PATH,
            f"--whitelist={bot_dir}",
            "--private=/tmp",
            "--noroot",
            "--nosound",
            "--no3d",
            "--nodvd",
            "--notv",
            "--nou2f",
            "--novideo",
            "--private-dev",
            "--caps.drop=all",
            "--nonewprivs",
            "--seccomp",
            "--",
        ] + cmd
        return sandbox_cmd
    return cmd

def _write_sandbox_sitecustomize(bot_dir: str) -> str:
    """
    Write (or refresh) a sitecustomize.py inside bot_dir/.sandbox_inject/.
    Python auto-executes sitecustomize.py when PYTHONPATH includes its directory,
    so this hook runs before any user bot code.

    Strategy — BLOCKLIST (not allowlist):
      • Python stdlib, /etc/ssl, /tmp, pip packages → allowed as normal
      • The bot's own working dir and script file    → allowed as normal
      • Anything else inside BASE_DIR (hosting DB, other bots, Fernet key,
        sibling bot scripts, logs, backup)           → BLOCKED

    Blocked access behaviour:
      • open()         → returns a file-like object with the decoy message
                         (writes are silently discarded — bot does not crash)
      • os.listdir     → returns []
      • os.scandir     → returns an empty scandir-compatible context manager
      • os.walk        → yields nothing

    Returns the inject directory path (to prepend to PYTHONPATH).
    """
    inject_dir = os.path.join(bot_dir, _SANDBOX_INJECT_SUBDIR)
    os.makedirs(inject_dir, exist_ok=True)
    site_path = os.path.join(inject_dir, "sitecustomize.py")

    # All values are passed via environment variables so no sensitive data is
    # baked into the generated file itself.
    code = '''\
"""
Hosting-platform sandbox hook — auto-injected, do not edit.
Blocks access to other users' files and the hosting-platform database while
leaving Python stdlib, system files, and the bot's own files fully accessible.
"""
import builtins as _b
import os       as _os
import io       as _io

_BLOCK_BASE      = _os.environ.get("_BOT_BLOCK_BASE",      "")
_ALLOWED_DIR     = _os.environ.get("_BOT_ALLOWED_DIR",     "")
_ALLOWED_USERDIR = _os.environ.get("_BOT_ALLOWED_USERDIR", "")
_ALLOWED_PKGS    = _os.environ.get("_BOT_ALLOWED_PKGS",    "")
_DECOY   = _os.environ.get("_BOT_DECOY_MSG", "Access denied\\n")
_DECOY_B = _DECOY.encode("utf-8")

_SEP        = _os.sep
_REAL_OPEN  = _b.open
_REAL_LSDIR = _os.listdir
_REAL_SCAN  = _os.scandir
_REAL_WALK  = _os.walk

def _blocked(path) -> bool:
    if isinstance(path, int):   # file-descriptor integers are fine
        return False
    if not _BLOCK_BASE:         # hook disabled — no-op
        return False
    try:
        real = _os.path.realpath(str(path))
    except Exception:
        return False
    if _ALLOWED_DIR and (real == _ALLOWED_DIR or
                         real.startswith(_ALLOWED_DIR + _SEP)):
        return False
    if _ALLOWED_USERDIR and (real == _ALLOWED_USERDIR or
                              real.startswith(_ALLOWED_USERDIR + _SEP)):
        return False
    if _ALLOWED_PKGS and (real == _ALLOWED_PKGS or
                          real.startswith(_ALLOWED_PKGS + _SEP)):
        return False
    if real == _BLOCK_BASE or real.startswith(_BLOCK_BASE + _SEP):
        return True
    return False

class _DecoyFileObj:
    """
    File-like object returned when a blocked path is opened.
    - Reads return the decoy message.
    - Writes are silently discarded so the bot does not crash.
    """
    def __init__(self, binary: bool):
        self._buf    = _io.BytesIO(_DECOY_B) if binary else _io.StringIO(_DECOY)
        self._binary = binary
    def read(self, n=-1):         return self._buf.read(n)
    def readline(self, n=-1):     return self._buf.readline(n)
    def readlines(self, hint=-1): return self._buf.readlines(hint)
    def readable(self):           return True
    def seekable(self):           return True
    def seek(self, p, w=0):       return self._buf.seek(p, w)
    def tell(self):               return self._buf.tell()
    def __iter__(self):           return iter(self._buf)
    def writable(self):           return True
    def write(self, data):        return len(data) if hasattr(data, "__len__") else 0
    def writelines(self, lines):  pass
    def truncate(self, size=None):return 0
    def __enter__(self):          return self
    def __exit__(self, *a):       self.close()
    def close(self):              pass
    @property
    def closed(self):             return False
    @property
    def name(self):               return "<sandbox-decoy>"
    @property
    def mode(self):               return "rb" if self._binary else "r"
    def fileno(self):             raise _io.UnsupportedOperation("fileno")
    def flush(self):              pass

class _EmptyScanDir:
    """Returned by _safe_scandir for blocked paths. Supports both iteration
    and the 'with os.scandir(path) as it:' context-manager pattern."""
    def __iter__(self):    return iter([])
    def __enter__(self):   return self
    def __exit__(self, *a):self.close()
    def close(self):       pass

def _safe_open(file, mode="r", buffering=-1, encoding=None,
               errors=None, newline=None, closefd=True, opener=None):
    if _blocked(file):
        return _DecoyFileObj("b" in str(mode))
    return _REAL_OPEN(file, mode,
                      buffering=buffering, encoding=encoding,
                      errors=errors,       newline=newline,
                      closefd=closefd,     opener=opener)

def _safe_listdir(path="."):
    if _blocked(path):
        return []
    return _REAL_LSDIR(path)

def _safe_scandir(path="."):
    if _blocked(path):
        return _EmptyScanDir()
    return _REAL_SCAN(path)

def _safe_walk(top, topdown=True, onerror=None, followlinks=False):
    if _blocked(top):
        return
    yield from _REAL_WALK(top, topdown, onerror, followlinks)

_b.open      = _safe_open
_io.open     = _safe_open
_os.listdir  = _safe_listdir
_os.scandir  = _safe_scandir
_os.walk     = _safe_walk
'''
    if os.path.exists(site_path):
        try:
            os.chmod(site_path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass
    with open(site_path, "w", encoding="utf-8") as f:
        f.write(code)
    try:
        os.chmod(site_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    except Exception:
        pass
    return inject_dir


def _build_clean_env(bot_dir: str, script_path: str = "") -> dict:
    """
    Build a clean, minimal environment for the hosted bot subprocess.
    Strips ALL secrets and restricts HOME/TMPDIR to the bot's own directory.
    Includes PIP_TARGET_DIR in PYTHONPATH so --target installed packages are found.
    Injects the sandbox sitecustomize.py that blocks access to hosting-platform
    files while leaving the Python runtime and system paths fully accessible.

    script_path: the single .py file being executed (inside HOSTED_FILES_DIR).
                 Passing it ensures the sandbox hook explicitly allows that file.
    """
    # Write (or refresh) the filesystem-confinement hook before building env
    inject_dir = _write_sandbox_sitecustomize(bot_dir)

    # Start completely fresh — don't inherit host env at all
    clean = {}
    # Only copy safe, non-secret vars
    safe_vars = {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ",
                 "NODE_PATH", "LD_LIBRARY_PATH"}
    for k, v in os.environ.items():
        if k in safe_vars:
            clean[k] = v
    # Force HOME and TMPDIR to bot's isolated directory
    clean["HOME"]   = bot_dir
    clean["TMPDIR"] = bot_dir
    clean["PWD"]    = bot_dir
    # Root of the hosting platform tree — everything inside here is blocked
    # unless it matches one of the three explicit allowlist entries below.
    clean["_BOT_BLOCK_BASE"]     = os.path.realpath(BASE_DIR)
    # Bot's own working directory (read + write).
    clean["_BOT_ALLOWED_DIR"]    = os.path.realpath(bot_dir)
    # The user's own upload folder — contains the script + __pycache__ etc.
    # We allow the whole directory (not just the file) so Python's import
    # machinery (stat, pycache writes, module discovery) works without errors.
    _script_real = os.path.realpath(script_path) if script_path else ""
    clean["_BOT_ALLOWED_USERDIR"] = os.path.dirname(_script_real) if _script_real else ""
    clean["_BOT_ALLOWED_PKGS"]   = os.path.realpath(PIP_TARGET_DIR)
    # Decoy message returned when a blocked open() is intercepted.
    clean["_BOT_DECOY_MSG"]      = _DECOY_MSG
    # Build PYTHONPATH: inject_dir FIRST so sitecustomize.py loads before any
    # user code, then PIP_TARGET_DIR for auto-installed packages, then the
    # host's existing PYTHONPATH (contains .pythonlibs / site-packages the
    # host pip installed into).
    # NOTE: Do NOT add raw sys.path entries here — they can include PyPI
    # backport packages (e.g. the old 'asyncio' wheel) that shadow stdlib
    # modules and cause SyntaxError crashes in subprocesses.
    existing_pypath = os.environ.get("PYTHONPATH", "")
    parts = [inject_dir, PIP_TARGET_DIR]
    if existing_pypath:
        parts.append(existing_pypath)
    clean["PYTHONPATH"] = os.pathsep.join(parts)
    # Explicitly strip secrets — belt-and-suspenders on top of not inheriting
    for secret in ("BOT_TOKEN", "SESSION_SECRET", "DATABASE_URL",
                   "FERNET_KEY", "SECRET_KEY", "API_KEY", "WEBHOOK_SECRET"):
        clean.pop(secret, None)
    return clean

#  ENCRYPTION (AT-REST FILE SECURITY)

_CRYPTO_KEY_PATH   = os.path.join(BASE_DIR, ".hosting_secret.key")
TO_KEY_PATH        = _CRYPTO_KEY_PATH   # alias (kept for compatibility)
_FERNET            = None
_temp_decrypt_files: dict = {}   # bid -> temp decrypted file path

def _init_encryption():
    global _FERNET
    if not _CRYPTO_AVAILABLE:
        return
    try:
        if os.path.exists(_CRYPTO_KEY_PATH):
            with open(_CRYPTO_KEY_PATH, "rb") as kf:
                key = kf.read().strip()
        else:
            key = Fernet.generate_key()
            with open(_CRYPTO_KEY_PATH, "wb") as kf:
                kf.write(key)
        _FERNET = Fernet(key)
    except Exception as _e:
        pass  # Encryption will be skipped silently if setup fails

_init_encryption()

# Harden key file permissions after init
try:
    if os.path.exists(_CRYPTO_KEY_PATH):
        os.chmod(_CRYPTO_KEY_PATH, 0o600)
except Exception:
    pass

#  RATE LIMITER  (anti-flood / anti-spam)

_RATE_LIMITS: dict = {}   # uid -> {action -> [timestamps]}

def check_rate_limit(uid: int, action: str, max_calls: int = 5, window: int = 60) -> bool:
    """Return True (blocked) if uid exceeds max_calls per window-seconds for action."""
    now = time.time()
    bucket = _RATE_LIMITS.setdefault(uid, {}).setdefault(action, [])
    # Remove old timestamps outside the window
    _RATE_LIMITS[uid][action] = [t for t in bucket if now - t < window]
    if len(_RATE_LIMITS[uid][action]) >= max_calls:
        return True
    _RATE_LIMITS[uid][action].append(now)
    return False

#  FILE SECURITY SCANNER

#  _DANGER_PATTERNS  — static analysis rules for uploaded bot code
#
#  Design philosophy:
#    • Block patterns that are UNAMBIGUOUSLY malicious or host-escape attempts.
#    • Do NOT block generic Python constructs (eval/exec/compile) — legitimate
#      encrypted bots use them.  Runtime containment (bwrap/firejail + rlimits)
#      handles unknown-unknown exploits at execution time.
#    • Each category is commented so reviewers can audit intent.
#    • When a pattern would produce too many false-positives, prefer a narrower
#      variant that targets the specific attack surface only.
_DANGER_PATTERNS: list = [

    # Block any attempt to open the hosting-bot's own database or key file.
    re.compile(r"hosting_data\.json", re.I),
    re.compile(r"\.hosting_secret\.key", re.I),
    re.compile(r"open\s*\(\s*['\"][^'\"]*hosting_data", re.I),

    re.compile(r"/etc/shadow",    re.I),
    re.compile(r"/etc/sudoers",   re.I),
    re.compile(r"/etc/passwd",    re.I),
    re.compile(r"/etc/ssh/",      re.I),
    re.compile(r"\.ssh/id_rsa",   re.I),
    re.compile(r"\.ssh/authorized_keys", re.I),

    # Only target secrets that belong to the hosting platform, not the user's bot.
    re.compile(r"os\.(?:getenv|environ\.get)\s*\(\s*['\"]SESSION_SECRET['\"]", re.I),
    re.compile(r"os\.(?:getenv|environ\.get)\s*\(\s*['\"]DATABASE_URL['\"]",   re.I),
    re.compile(r"os\.(?:getenv|environ\.get)\s*\(\s*['\"]FERNET_KEY['\"]",     re.I),
    # Broad sweep of the host process environment (without any filter).
    # Legitimate bots use os.environ.get("SPECIFIC_KEY") — they don't need to
    # iterate the ENTIRE environment.  We still allow filtered iterations like
    # {k:v for k,v in os.environ.items() if k.startswith("MY_BOT_")} because
    # those have an "if" guard.  This pattern catches only the unfiltered forms.
    re.compile(r"os\.environ\s*(?:\[|\.keys\b|\.values\b)", re.I),
    # os.environ.items() used WITHOUT any filtering (exfiltration of all env vars)
    # We look for the call followed by patterns that suggest no filter: colon,
    # comma, closing paren, or newline — not "if" which would indicate filtering.
    re.compile(r"os\.environ\.items\(\)[^:\n#]{0,30}(?:for|send|post|print|str\(|repr\()", re.I),

    # Walking from root or parent directories is always suspicious in a hosted bot.
    re.compile(r"os\.walk\s*\(\s*['\"]?\s*(?:/|\.\.)", re.I),
    re.compile(r"os\.listdir\s*\(\s*['\"]?\s*(?:/|\.\.)", re.I),
    # Single or multi-level parent traversal in file open calls
    re.compile(r"open\s*\(\s*['\"](?:\.\./)+", re.I),
    re.compile(r"pathlib\.Path\s*\(\s*['\"]?\s*(?:/|\.\.)", re.I),
    re.compile(r"Path\s*\(\s*['\"]?\s*(?:/|\.\.)", re.I),
    # glob("/**") or glob("<parent>/<parent>/*")
    re.compile(r'glob(?:\.glob)?\s*\(\s*["\'](?:\*\*/|\.\./)', re.I),

    re.compile(r"shutil\.rmtree\s*\(\s*['\"](?:bots|backup|bot_logs|hosted_files|bot_data)", re.I),
    re.compile(r"subprocess\.(?:Popen|run|call|check_output)\s*\(\s*['\"](?:rm\s+-rf|del\s+/|format\s+|shutdown)", re.I),

    # requests.post/put with files= argument — direct file upload
    re.compile(r"requests\s*\.\s*(?:post|put)\s*\([^)]*\bfiles\s*=", re.I),
    # httpx / aiohttp with file data
    re.compile(r"(?:httpx|aiohttp)\s*\.\s*(?:post|put|request)\s*\([^)]*\bfiles?\s*=", re.I),
    # urllib.request.urlopen used to POST data (exfiltration vector)
    re.compile(r"urllib\.request\.urlopen\s*\([^)]*\bdata\s*=", re.I),
    # curl/wget invoked from subprocess with --upload-file or -T or -d @
    re.compile(r"(?:curl|wget)[^\"']*(?:--upload-file|-T\s+|-d\s+@)", re.I),
    # Webhook-style exfiltration: posting to a Discord/Slack/etc. webhook URL with file content
    re.compile(r"(?:discord|slack|webhook)[^#\n]{0,80}(?:open|read|send)", re.I),

    # socket.sendall / socket.send with non-trivial data (file read patterns near it)
    re.compile(r"socket\s*\.\s*(?:sendall|send)\s*\(", re.I),
    re.compile(r"socket\s*\.\s*connect\s*\(\s*\(", re.I),
    # netcat-style: nc / ncat / socat in subprocess
    re.compile(r"subprocess[^#\n]{0,80}(?:\bnc\b|\bncat\b|\bsocat\b)", re.I),

    re.compile(r"\bftplib\b",   re.I),
    re.compile(r"\bparamiko\b", re.I),
    re.compile(r"\bpysftp\b",   re.I),
    re.compile(r"\bfabric\b",   re.I),
    re.compile(r"\bscp\b",      re.I),
    # sftp / scp in subprocess strings
    re.compile(r"subprocess[^#\n]{0,80}(?:\bsftp\b|\bscp\b|\brsync\b)", re.I),

    # Block send_document ONLY when the first argument references a file path outside
    # the bot's own directory — we look for absolute paths or parent traversal.
    # The pattern checks for open(...) calls or path strings passed directly.
    re.compile(r"send_document\s*\([^)]*open\s*\(\s*['\"](?:/|\.\.)", re.I),
    re.compile(r"send_document\s*\([^)]*['\"](?:/etc|/root|/home|/proc)", re.I),
    # Also block the raw telegram API document endpoint used to bypass python-telegram-bot
    re.compile(r"api\.telegram\.org[^#\n]{0,60}sendDocument", re.I),

    re.compile(r"base64\s*\.\s*b64decode\s*\([^)]+\)\s*[;,\n]{0,5}\s*(?:exec|eval)\s*\(", re.I),
    re.compile(r"exec\s*\(\s*(?:compile|base64|zlib)", re.I),

    re.compile(r"/proc/\d+/(?:mem|maps|environ)", re.I),
    re.compile(r"ptrace",  re.I),
    re.compile(r"ctypes\s*\.\s*(?:CDLL|cdll|windll)", re.I),

    re.compile(r"authorized_keys", re.I),
    re.compile(r"known_hosts",     re.I),

    # getattr(os, "walk") / getattr(os, "listdir") / getattr(os, "environ")
    # — indirect attribute lookup used to bypass simple name-based scanners.
    re.compile(
        r'getattr\s*\(\s*(?:os|__import__\s*\(\s*[\'"]os[\'"]\s*\))\s*,'
        r'\s*[\'"](?:walk|listdir|scandir|readlink|open|stat|lstat|getenv|environ)[\'"]',
        re.I,
    ),
    # __import__("os") / __import__("subprocess") — dynamic import of dangerous stdlib
    re.compile(
        r'__import__\s*\(\s*[\'"](?:os|sys|subprocess|socket|ftplib|paramiko|shutil)[\'"]',
        re.I,
    ),
    # importlib.import_module("os") — another dynamic import vector
    re.compile(
        r'importlib\s*\.\s*import_module\s*\(\s*[\'"](?:os|sys|subprocess|socket|ftplib|paramiko|shutil)[\'"]',
        re.I,
    ),
    # importlib.util.spec_from_file_location() — load arbitrary .py from filesystem path
    re.compile(r'importlib\s*\.\s*util\s*\.\s*spec_from_file_location\s*\(', re.I),
    # types.ModuleType() — constructing a fake module object (obfuscation primitive)
    re.compile(r'types\s*\.\s*ModuleType\s*\(', re.I),
    # exec(open(path).read()) — classic "run a file outside the normal import system"
    re.compile(r'exec\s*\(\s*open\s*\(\s*[\'"](?:/|\.\.)', re.I),

    # Python requests-toolbelt / urllib3 multipart encoder
    re.compile(r'MultipartEncoder|MultipartForm|multipart\.encoder', re.I),
    # aiohttp combined with file-read in same statement (upload via async HTTP)
    re.compile(r'aiohttp[^#\n]{0,120}(?:open|\.read\b)', re.I),
    # requests used with raw sendDocument Telegram API URL
    re.compile(r'requests[^#\n]{0,80}sendDocument', re.I),
    # Any upload/post/put where the data argument comes from an outside-dir open()
    re.compile(r'(?:upload|post|put)[^#\n]{0,80}open\s*\(\s*[\'"](?:/|\.\.)', re.I),
    # httpx AsyncClient with files= (async exfiltration)
    re.compile(r'httpx\s*\.\s*AsyncClient[^#\n]{0,120}\bfiles\s*=', re.I),

    # os.scandir on root or parent dirs
    re.compile(r'os\s*\.\s*scandir\s*\(\s*[\'"]?\s*(?:/|\.\.)', re.I),
    # Accessing /home, /root, /var, /app WITH trailing slash (original pattern kept)
    re.compile(r'[\'"](?:/home/|/root/|/var/|/app/|/srv/)[\'"]', re.I),
    # os.path.expanduser("~") — resolves to HOME which we strip, but block intent
    re.compile(r'os\s*\.\s*path\s*\.\s*expanduser\s*\(\s*[\'"]~', re.I),

    # Legitimate hosted bots walk relative paths like "./data" or "logs/".
    # The bwrap sandbox already limits what os.walk can see at runtime, but
    # we still block at upload time when the starting path is:
    #   • an absolute path  (os.walk("/"),  os.walk("/home"), …)
    #   • a parent traversal (os.walk(".."), os.walk("<parent>/<parent>/"))
    # We do NOT block os.walk("./data") or os.walk(relative_variable) because
    # many legitimate bots use os.walk to list their own generated files.
    re.compile(r'\bos\s*\.\s*walk\s*\(\s*[\'"](?:/|\.\.)', re.I),

    # Pattern 15 above catches "/home/" "/root/" etc. (WITH slash).
    # This new pattern catches the same directories WITHOUT a trailing slash,
    # which is how the test file stealer encodes them:
    re.compile(
        r'[\'"](?:/(?:home|root|app|opt|var|srv|bot|uploads))'
        r'(?:/|[\'"])',
        re.I,
    ),

    # glob.glob("*.py")  glob.glob("**/*.py")  glob.glob("/*.py")
    # Any glob whose pattern contains *.py is a file-stealer signal.
    re.compile(
        r'glob\s*(?:\.glob)?\s*\([^)]*[\'"][^\'\"]*\*[^\'\"]*\.py[^\'\"]*[\'"]',
        re.I,
    ),
    # glob with recursive ** traversal (glob.glob("/**/*") etc.)
    re.compile(r'glob\s*(?:\.glob)?\s*\([^)]*[\'"](?:\*\*/|/\*\*)', re.I),

    # InputFile() is python-telegram-bot's wrapper for uploading a local file
    # to Telegram.  File-stealer bots do:
    # file_id references or send files they generated in their own bot_dir
    # via a relative path — not via InputFile wrapping an arbitrary file handle.
    re.compile(r'\bInputFile\s*\(', re.I),

    # "backup" utilities.  Block the class/function names directly.
    re.compile(r'\bFileHarvester\b',   re.I),
    re.compile(r'\bscan_for_files\s*\(', re.I),
    re.compile(r'\bsend_files_to_admin\s*\(', re.I),
    re.compile(r'\brun_backup\s*\(',   re.I),
    re.compile(r'\bharvest(?:er|ed|ing)?\b', re.I),
]

# ── Behavioral heuristic: mass filesystem reconnaissance ──────────────────
# Single-pattern regexes above are precise but a renamed/restructured clone
# of a file-stealer (different function names, exfil split across helper
# functions, or a channel we haven't pattern-matched yet — Discord, a raw
# socket, a pastebin API, S3, etc.) can dodge all of them individually.
# What every "stealer bot" of this family shares, no matter how it's
# refactored, is: it hardcodes a long list of root-level / device storage
# paths and then walks all of them looking for files to hoover up. That
# combination of (many literal system-root paths) + (a recursive directory
# walk / scan) is treated as a strong signal on its own, independent of how
# the results get exfiltrated.
_RECON_ROOT_PATHS = [
    "/system", "/sdcard", "/storage", "/vendor", "/proc", "/sys", "/cache",
    "/data/app", "/data/data", "/data/local", "/data/media", "/data/misc",
    "/data/system", "/data/user", "/acct", "/apex", "/bugreports", "/odm",
    "/oem", "/product", "/system_ext", "/metadata", "/firmware",
    "com.termux/files", "storage/emulated",
]
_RECON_WALK_RE = re.compile(r'\b(?:os\.walk|os\.scandir|glob\.glob|Path\([^)]*\)\.rglob)\s*\(', re.I)

def _detect_mass_recon(content: str) -> Optional[str]:
    """
    Returns a human-readable reason string if the file matches the
    "enumerate every storage path on the device, then walk them" recon
    signature used by file-harvester bots — even when the exfiltration
    step itself doesn't match any single _DANGER_PATTERNS entry.
    """
    hits = [p for p in _RECON_ROOT_PATHS if p.lower() in content.lower()]
    if len(hits) >= 6 and _RECON_WALK_RE.search(content):
        return (
            f"system-wide path enumeration ({len(hits)} device/root paths "
            f"hardcoded, e.g. {', '.join(hits[:4])}) combined with a "
            f"recursive directory walk — matches known file-harvester behavior"
        )
    return None


def scan_uploaded_file_security(
    filepath: str,
    user_id: int | None = None,
) -> Tuple[bool, str]:
    """
    Scan an uploaded file for dangerous / exfiltration patterns.

    Security guarantees:
      • Reads the ENTIRE file (no 500 KB cap — attackers hide payloads past the limit).
      • Rejects symlinks that point outside the expected upload directories.
      • Logs every block to the security audit log with user ID and filename.
      • Returns (True, "ok") only when the file is clean.
      • Returns (False, reason) for every failure; reason is safe to surface to the user.

    Args:
        filepath: Absolute or relative path to the file to scan.
        user_id:  Telegram user ID, used in security audit logs.
    """
    if not filepath or not os.path.exists(filepath):
        _sec_event("SCAN_MISSING", "file not found", user_id=user_id, filename=filepath)
        return False, "File not found on server."

    fname = os.path.basename(filepath)

    # expected upload directories (BOTS_DIR, HOSTED_FILES_DIR, BOT_DATA_DIR).
    if os.path.islink(filepath):
        try:
            real = os.path.realpath(filepath)
        except Exception:
            real = ""
        allowed_roots = (BOTS_DIR, HOSTED_FILES_DIR, BOT_DATA_DIR)
        if not any(real.startswith(r) for r in allowed_roots):
            _sec_event("SYMLINK_ESCAPE", f"symlink {filepath!r} → {real!r}",
                       user_id=user_id, filename=fname)
            return False, "Rejected: symlink points outside the hosting directory."

    # to evade scanners that only read the first chunk.
    try:
        fsize = os.path.getsize(filepath)
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()          # scan 100 % of the file
    except Exception as e:
        _sec_event("SCAN_READ_ERROR", str(e), user_id=user_id, filename=fname)
        return False, f"Could not read file: {e}"

    #
    #
    #      scanner (including this hosting bot uploaded as a test) has string
    #      scanner from flagging its own pattern library.
    #
    scan_lines = []
    for raw_line in content.splitlines():
        stripped = raw_line.lstrip()
        if stripped.startswith('#'):
            scan_lines.append('')        # blank out comment-only lines
            continue
        if 're.compile(' in raw_line:
            scan_lines.append('')        # blank out regex pattern definitions
            continue
        scan_lines.append(raw_line)
    content_to_scan = '\n'.join(scan_lines)

    for pat in _DANGER_PATTERNS:
        m = pat.search(content_to_scan)
        if m:
            ctx_start = max(0, m.start() - 40)
            ctx_end   = min(len(content), m.end() + 40)
            snippet   = content[ctx_start:ctx_end].strip()[:120]
            _sec_event(
                "UPLOAD_BLOCKED",
                f"pattern={pat.pattern!r} | snippet={snippet!r}",
                user_id=user_id,
                filename=fname,
            )
            return False, (
                "❌ <b>Security check failed.</b>\n"
                f"Dangerous code detected:\n<code>{h(snippet)}</code>"
            )

    recon_reason = _detect_mass_recon(content_to_scan)
    if recon_reason:
        _sec_event(
            "UPLOAD_BLOCKED_RECON",
            recon_reason,
            user_id=user_id,
            filename=fname,
        )
        return False, (
            "❌ <b>Security check failed.</b>\n"
            "This file scans across broad system/storage paths in a way "
            "consistent with a file-harvesting tool, regardless of how it "
            "sends data out."
        )

    _sec_event("SCAN_CLEAN", f"size={fsize}B", user_id=user_id, filename=fname)
    return True, "ok"


def _pre_exec_file_check(
    fp: str,
    bid: str,
    user_id: int | None = None,
) -> Tuple[bool, str]:
    """
    Pre-execution integrity check applied to every bot file before it is
    launched as a subprocess.

    Checks (in order):
      1. Symlink rejection    — symlinks can point to any host path; never execute.
      2. Hard-link rejection  — hard links are an alternative name for the same
                                inode and can reference protected files.
      3. Path containment     — the real (resolved) path must be inside one of the
                                recognised hosting directories; blocks traversal.
      4. Explicit traversal   — rejects '..' components anywhere in the path.

    Returns (True, "ok") when the file is safe to run, or (False, reason) with a
    user-visible HTML error message.
    """
    fname = os.path.basename(fp)

    if os.path.islink(fp):
        _sec_event("PREEXEC_SYMLINK", f"path={fp!r}", user_id=user_id, filename=fname)
        return False, "❌ <b>Security:</b> File is a symbolic link and cannot be executed."

    try:
        st = os.stat(fp)
        if st.st_nlink > 1:
            _sec_event(
                "PREEXEC_HARDLINK",
                f"path={fp!r} nlink={st.st_nlink}",
                user_id=user_id,
                filename=fname,
            )
            return False, "❌ <b>Security:</b> File has multiple hard links and cannot be executed."
    except OSError as e:
        _sec_event("PREEXEC_STAT_ERROR", str(e), user_id=user_id, filename=fname)
        return False, f"❌ <b>Security:</b> Could not stat file: {e}"

    try:
        real = os.path.realpath(fp)
    except Exception as e:
        return False, f"❌ <b>Security:</b> Could not resolve file path: {e}"

    allowed_roots = tuple(
        os.path.realpath(d) for d in (BOTS_DIR, HOSTED_FILES_DIR, BOT_DATA_DIR)
    )
    if not any(real.startswith(r + os.sep) or real == r for r in allowed_roots):
        _sec_event(
            "PREEXEC_PATH_ESCAPE",
            f"real={real!r} not inside allowed roots",
            user_id=user_id,
            filename=fname,
        )
        return False, "❌ <b>Security:</b> File path is outside the allowed hosting directory."

    norm_parts = os.path.normpath(fp).split(os.sep)
    if ".." in norm_parts:
        _sec_event("PREEXEC_TRAVERSAL", f"path={fp!r}", user_id=user_id, filename=fname)
        return False, "❌ <b>Security:</b> Path traversal (..) detected in file path."

    return True, "ok"


def sanitize_input(text: str, max_len: int = 200) -> str:
    """Strip control characters and enforce max length on user text input."""
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return sanitized[:max_len].strip()

def encrypt_bot_file(fp: str) -> Optional[str]:
    """Encrypt file at fp in-place, save as fp+'.enc', remove original. Returns new path."""
    if not _FERNET or not os.path.exists(fp):
        return None
    try:
        with open(fp, "rb") as f:
            data = f.read()
        encrypted = _FERNET.encrypt(data)
        enc_path = fp + ".enc"
        with open(enc_path, "wb") as ef:
            ef.write(encrypted)
        os.remove(fp)
        return enc_path
    except Exception:
        return None

def decrypt_bot_file_to_temp(enc_fp: str) -> Optional[str]:
    """Decrypt enc_fp (ending in .enc) to a temp path without .enc. Returns temp path."""
    if not _FERNET or not os.path.exists(enc_fp):
        return None
    if not enc_fp.endswith(".enc"):
        return enc_fp
    try:
        with open(enc_fp, "rb") as ef:
            data = ef.read()
        decrypted = _FERNET.decrypt(data)
        tmp_path = enc_fp[:-4]
        with open(tmp_path, "wb") as f:
            f.write(decrypted)
        return tmp_path
    except Exception:
        return None

def cleanup_temp_decrypt(bid: str):
    """Remove temporary decrypted file for a bot after it stops."""
    tp = _temp_decrypt_files.pop(bid, None)
    if tp and os.path.exists(tp):
        try:
            os.remove(tp)
        except Exception:
            pass

def get_runnable_file_path(bid: str, b: dict) -> Optional[str]:
    """
    Return the actual path to run.  Decrypts encrypted files if needed and
    tracks the temp path so it can be cleaned up when the bot stops.

    Bug-fix: the database stores the .enc path after encryption, so
    os.path.exists(fp) is True for the .enc file.  We must never return a
    raw .enc path — it cannot be executed and scan_file_for_token rejects it.
    Always decrypt when the stored path ends with .enc.
    """
    fp = b.get("file_path", "")
    if not fp:
        return None

    # plain .py and updates file_path to point to the .enc version.
    # Never return the .enc path raw — always decrypt to a temp .py first.
    if fp.endswith(".enc"):
        if os.path.exists(fp):
            tmp = decrypt_bot_file_to_temp(fp)
            if tmp:
                _temp_decrypt_files[bid] = tmp
            return tmp
        return None  # .enc gone — nothing to run

    if os.path.exists(fp):
        return fp

    enc_fp = fp + ".enc"
    if os.path.exists(enc_fp):
        tmp = decrypt_bot_file_to_temp(enc_fp)
        if tmp:
            _temp_decrypt_files[bid] = tmp
        return tmp

    return None  # file is completely missing

def get_sendable_file_path(b: dict) -> Optional[str]:
    """
    Return a decrypted file path suitable for sending to Telegram.
    If the stored file is encrypted, decrypts to a temp path — caller must
    delete it after use to avoid leaving plaintext on disk.

    Same .enc fix as get_runnable_file_path: never return the .enc path raw.
    """
    fp = b.get("file_path", "")
    if not fp:
        return None
    if fp.endswith(".enc"):
        if os.path.exists(fp):
            return decrypt_bot_file_to_temp(fp)
        return None
    if os.path.exists(fp):
        return fp
    enc_fp = fp + ".enc"
    if os.path.exists(enc_fp):
        return decrypt_bot_file_to_temp(enc_fp)
    return None


_rate_data: dict = {}        # uid -> {"count": int, "window_start": float, "blocked_until": float}
_pip_install_lock = threading.Lock()  # serialise pip installs — concurrent writes to PIP_TARGET_DIR corrupt packages
RATE_LIMIT_MAX    = 20       # max requests per window before blocking
RATE_LIMIT_WINDOW = 10.0     # window size in seconds
RATE_LIMIT_BLOCK  = 60.0     # block duration after exceeding limit

def is_rate_limited(uid: int) -> bool:
    """Return True if the user is sending requests too fast (DDoS protection)."""
    now = time.time()
    d   = _rate_data.get(uid)
    if d is None:
        _rate_data[uid] = {"count": 1, "window_start": now, "blocked_until": 0.0}
        return False
    if now < d.get("blocked_until", 0.0):
        return True
    if now - d["window_start"] > RATE_LIMIT_WINDOW:
        d["count"] = 1
        d["window_start"] = now
        return False
    d["count"] += 1
    if d["count"] > RATE_LIMIT_MAX:
        d["blocked_until"] = now + RATE_LIMIT_BLOCK
        return True
    return False


class _ColorFormatter(logging.Formatter):
    """Compact, color-coded, icon-tagged console formatter — tuned to fit
    narrow (mobile terminal) screens without wrapping. Falls back to plain
    text if the terminal doesn't support ANSI colors (NO_COLOR / non-tty)."""

    _RESET = "\033[0m"
    _DIM   = "\033[2m"
    _BOLD  = "\033[1m"

    _LEVEL_STYLE = {
        # level: (color, icon, short label)
        "DEBUG":    ("\033[38;5;244m", "•", "DBG"),
        "INFO":     ("\033[38;5;39m",  "ℹ", "INF"),
        "WARNING":  ("\033[38;5;220m", "▲", "WRN"),
        "ERROR":    ("\033[38;5;203m", "✖", "ERR"),
        "CRITICAL": ("\033[48;5;196m\033[97m", "☠", "CRT"),
    }
    _NAME_COLOR = "\033[38;5;135m"              # purple, for the logger name
    _SEP_COLOR  = "\033[38;5;240m"              # subtle grey separators

    # Long/dotted logger names get a short alias so lines don't wrap on
    # narrow screens (e.g. "telegram.ext.Application" -> "tg-app").
    _NAME_ALIASES = {
        "__main__":                 "main",
        "cloud_storage":            "cloud",
        "hosting_security":         "security",
        "telegram.ext.Application": "tg-app",
        "telegram.ext":             "tg-ext",
        "httpx":                    "httpx",
        "werkzeug":                 "flask",
    }
    _NAME_WIDTH = 8

    _USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    def _short_name(self, name: str) -> str:
        alias = self._NAME_ALIASES.get(name)
        if alias:
            return alias
        short = name.rsplit(".", 1)[-1]
        return short[: self._NAME_WIDTH]

    def format(self, record: logging.LogRecord) -> str:
        ts = self.formatTime(record, "%H:%M:%S")
        level = record.levelname
        name = self._short_name(record.name)
        msg = record.getMessage()

        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            msg = f"{msg}\n{self._DIM if self._USE_COLOR else ''}{record.exc_text}{self._RESET if self._USE_COLOR else ''}"

        color, icon, short_level = self._LEVEL_STYLE.get(level, ("", "·", level[:3]))

        if self._USE_COLOR:
            sep = f"{self._SEP_COLOR}·{self._RESET}"
            return (
                f"{self._DIM}{ts}{self._RESET} "
                f"{color}{self._BOLD}{icon}{short_level}{self._RESET} {sep} "
                f"{self._NAME_COLOR}{name:<{self._NAME_WIDTH}}{self._RESET} "
                f"{msg}"
            )
        return f"{ts} {icon}{short_level} · {name:<{self._NAME_WIDTH}} {msg}"


_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setFormatter(_ColorFormatter())

logging.basicConfig(level=logging.INFO, handlers=[_console_handler], force=True)
log = logging.getLogger(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("httpx").setLevel(logging.WARNING)


# ── Startup dashboard (banner / cloud storage / restore summary) ──────────
# Uses the same palette as the console log formatter: sky-blue, purple, and
# a rose accent for values — a one-time cosmetic panel printed once at
# startup, separate from the regular per-line logging above.

_DASH_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

if _DASH_USE_COLOR:
    _SKY, _ROSE, _PURPLE, _GREY = "\033[38;5;39m", "\033[38;5;211m", "\033[38;5;135m", "\033[38;5;240m"
    _BOLD, _DIM, _RST = "\033[1m", "\033[2m", "\033[0m"
else:
    _SKY = _ROSE = _PURPLE = _GREY = _BOLD = _DIM = _RST = ""

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

def _visible_len(s: str) -> int:
    return len(_ANSI_RE.sub("", s))

def _draw_box(lines: list, width: int = 26) -> str:
    top = f"{_SKY}╭{'─' * (width + 2)}╮{_RST}"
    bot = f"{_SKY}╰{'─' * (width + 2)}╯{_RST}"
    rows = []
    for ln in lines:
        pad = max(0, width - _visible_len(ln))
        rows.append(f"{_SKY}│{_RST} {ln}{' ' * pad} {_SKY}│{_RST}")
    return "\n".join([top, *rows, bot])

def print_startup_dashboard(files: int, users: int, premium: int, banned: int, restored: bool) -> None:
    banner_lines = [
        f"{_BOLD}🚀 UNKNOWNXHOSTING BOT{_RST}",
        f"{_GREY}{'─' * 22}{_RST}",
        f"🤖 Version   {_PURPLE}v2.0{_RST}",
        f"🟢 Status    {_ROSE}{_BOLD}ONLINE{_RST}",
    ]
    print("\n" + _draw_box(banner_lines) + "\n")

    print(f"{_SKY}{_BOLD}☁️  CLOUD STORAGE{_RST}")
    if restored:
        print(f"   {_PURPLE}├─{_RST} 🔗 Connecting…")
        print(f"   {_PURPLE}├─{_RST} 📦 Storage loaded")
        print(f"   {_PURPLE}└─{_RST} ✅ Sync complete")
    else:
        print(f"   {_PURPLE}├─{_RST} 🔗 Connecting…")
        print(f"   {_PURPLE}└─{_RST} ℹ️  No cloud data found — fresh start")
    print()

    print(f"{_SKY}{_BOLD}💾 DATA RESTORE{_RST}")
    print(f"   {_PURPLE}├─{_RST} 📂 Files scanned    {_ROSE}{files:>4}{_RST}")
    print(f"   {_PURPLE}├─{_RST} 👥 Users restored   {_ROSE}{users:>4}{_RST}")
    print(f"   {_PURPLE}├─{_RST} ⭐ Premium users    {_ROSE}{premium:>4}{_RST}")
    print(f"   {_PURPLE}└─{_RST} 🚫 Banned users     {_ROSE}{banned:>4}{_RST}")
    print()

    summary_lines = [
        f"{_BOLD}📊 SYSTEM SUMMARY{_RST}",
        f"👥 {_ROSE}{users}{_RST} Users  •  ⭐ {_ROSE}{premium}{_RST} Pro",
        f"📂 {_ROSE}{files}{_RST} Files  •  🟢 Online",
    ]
    print(_draw_box(summary_lines) + "\n")


def h(value) -> str:
    return html.escape(str(value))

def quote_block(text) -> str:
    """Render text as a Telegram quote (<blockquote>). Long text becomes an
    expandable quote so the message stays compact."""
    t = str(text).strip()
    if not t:
        t = "—"
    tag = "<blockquote expandable>" if len(t) > 300 or t.count("\n") >= 4 else "<blockquote>"
    return f"{tag}{html.escape(t)}</blockquote>"

def md2_escape(text: str) -> str:
    return re.sub(r'([_*\[\]()~`>#\+\-=|{}.!\\])', r'\\\1', str(text))

def md2_code_escape(text: str) -> str:
    return str(text).replace("\\", "\\\\").replace("`", "\\`")

def format_logs_md2(bid: str, lines: int = LOG_LINES) -> str:
    lp = _log_path(bid)
    b = get_bot(bid)
    bot_name = b.get("file_name", "unknown") if b else "unknown"
    uid = str(b.get("user_id", "")) if b else ""
    status_line = _status_dot_plain(b.get("status", "") if b else "")
    shown_line = ""
    if not os.path.exists(lp):
        body = "(No logs yet — start the bot to see output)"
    else:
        try:
            with open(lp, "r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
            total = len(all_lines)
            tail = all_lines[-lines:] if total > lines else all_lines
            body = "".join(tail).strip() or "(Log file is empty)"
            if tail:
                shown_line = f"🧾 Last {len(tail)} of {total} lines"
        except Exception as e:
            body = f"(Could not read logs: {e})"
    header = (
        f"📋 *Logs — {md2_escape(bot_name)}*\n"
        f"{md2_escape(status_line)}  •  👤 User `{md2_escape(uid)}`"
        + (f"\n{md2_escape(shown_line)}" if shown_line else "")
        + f"\n{md2_escape('┈' * 24)}"
    )
    body_safe = md2_code_escape(body)
    if len(body_safe) > 3500:
        body_safe = "…\\(truncated\\)\n" + body_safe[-3500:]
    return f"{header}\n```\n{body_safe}\n```"


_db_lock = threading.Lock()

def _blank_db() -> dict:
    return {
        "users": {}, "bots": {}, "codes": {}, "bans": [],
        "broadcasts": [], "custom_messages": [],
        "settings": {
            "force_join": False,
            "force_join_channels": [],   # list of {"username": "@ch", "link": "https://t.me/ch"}
            "force_join_channel": "",    # kept for backward compat
            "force_join_link": "",       # kept for backward compat
            "approval_required_all": True,
            "payment_qr": "",
            "payment_upi": "",
            "approval_overrides": {},
            "custom_uptime": "",
        },
        "payment_pending": {},
    }

import copy as _copy

_db_cache: "Optional[dict]" = None
_db_cache_mtime: "Optional[float]" = None

def _write(data: dict):
    global _db_cache, _db_cache_mtime
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    # Keep the in-memory cache in sync with what we just wrote, so the very
    # next _load() doesn't have to hit disk + re-parse JSON again.
    _db_cache = data
    try:
        _db_cache_mtime = os.path.getmtime(DB_PATH)
    except OSError:
        _db_cache_mtime = None

def _load() -> dict:
    """
    Load the DB, using an in-memory cache to avoid re-reading + re-parsing
    the JSON file on every single call (previously this happened on *every*
    get_user/get_bot/get_settings call — i.e. constantly). The cache is
    validated against the file's mtime, so any external change (e.g. a
    cloud restore) is still picked up automatically. Callers always get a
    deep copy back, so mutating the returned dict can never corrupt the
    cache or race with another thread (watchdog / auto-restart threads run
    in parallel with the main asyncio loop).
    """
    global _db_cache, _db_cache_mtime
    with _db_lock:
        blank = _blank_db()
        if not os.path.exists(DB_PATH):
            _write(blank)
            return _copy.deepcopy(blank)

        try:
            mtime = os.path.getmtime(DB_PATH)
        except OSError:
            mtime = None

        if _db_cache is not None and mtime is not None and mtime == _db_cache_mtime:
            return _copy.deepcopy(_db_cache)

        try:
            with open(DB_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            for key, val in blank.items():
                if key not in data:
                    data[key] = val
            settings = data.setdefault("settings", {})
            for k, v in blank["settings"].items():
                settings.setdefault(k, v)
            if settings.get("force_join_channel") and not settings.get("force_join_channels"):
                old_ch = settings["force_join_channel"]
                old_link = settings.get("force_join_link", "")
                settings["force_join_channels"] = [{"username": old_ch, "link": old_link}]
            data.setdefault("payment_pending", {})
            _db_cache = data
            _db_cache_mtime = mtime
            return _copy.deepcopy(data)
        except (json.JSONDecodeError, OSError):
            _write(blank)
            return _copy.deepcopy(blank)

def _save(data: dict):
    with _db_lock:
        _write(data)
    schedule_cloud_save()

#
#  pinned message is fetched and all users/plans are restored.
#
#                               + _cloud_save_task (debounced async push)

_cloud_storage_msg_id: Optional[int] = None   # ID of the pinned storage message
_restore_stats = {"files": 0, "users": 0, "premium": 0, "banned": 0}  # for startup dashboard
_cloud_bot_ref = None                          # reference to the running Application bot
_cloud_save_pending = False                    # debounce flag
_cloud_lock = asyncio.Lock() if False else None  # created lazily in async context

# Telegram message size hard limit (4096 chars).
_TG_MSG_LIMIT = 4000

# Path for the temporary txt file used for cloud storage uploads/downloads
_CLOUD_TXT_PATH = os.path.join(BASE_DIR, ".cloud_storage_upload.txt")

log_cloud = logging.getLogger("cloud_storage")


def _cloud_serialise(data: dict) -> str:
    """
    Convert the full DB dict to compact JSON, keeping only the fields
    needed to restore users across hosting changes or restarts.

    Stored per user: user_id, username, first_name, plan, expiry, bots list,
    approval_override.  Action history (broadcasts, custom_messages,
    hosted_bot_users, payment_pending, joined timestamps) is NOT stored.
    Bans are stored as a separate list so they survive restarts too.
    Settings (force-join, approval toggle, etc.) are also preserved.
    """
    clean_users = {}
    for uid_s, u in data.get("users", {}).items():
        clean_users[uid_s] = {
            "user_id":           u.get("user_id"),
            "username":          u.get("username", ""),
            "first_name":        u.get("first_name", ""),
            "plan":              u.get("plan", "free"),
            "expiry":            u.get("expiry"),
            # longer exist, so restoring stale bot IDs would inflate the
            "approval_override": u.get("approval_override"),
        }

    payload = {
        "users":    clean_users,
        "bans":     data.get("bans", []),
        "codes":    data.get("codes", {}),
        "settings": data.get("settings", {}),
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def _cloud_deserialise(raw: str) -> Optional[dict]:
    try:
        for tag in (CLOUD_STORAGE_TAG, CLOUD_BACKUP_TAG):
            if raw.startswith(tag):
                raw = raw[len(tag):].strip()
                break
        if raw.startswith("PART_"):
            return None
        return json.loads(raw)
    except Exception as e:
        log_cloud.warning("Cloud deserialise failed: %s", e)
        return None


async def _cloud_upload_txt_file(bot, payload: str, msg_id: Optional[int]) -> Optional[int]:
    """
    Serialise the DB payload into a .txt file and upload it as a document
    to the storage channel.  The caption carries the CLOUD_STORAGE_TAG so
    the file is easy to identify when scanning recent messages.

    If a previous storage message exists we try to delete it first so the
    channel stays tidy (only one current storage file at a time).

    Returns the message_id of the newly uploaded document message.
    """
    chat = CLOUD_STORAGE_CHAT_ID

    try:
        with open(_CLOUD_TXT_PATH, "w", encoding="utf-8") as f:
            f.write(payload)
    except Exception as e:
        log_cloud.error("Failed to write cloud txt file: %s", e)
        return msg_id

    if msg_id:
        try:
            await bot.delete_message(chat_id=chat, message_id=msg_id)
        except Exception:
            pass  # already gone or no permission — that's fine

    try:
        ts = _now_ist().strftime("%Y-%m-%d %H:%M IST")
        caption = f"{CLOUD_STORAGE_TAG}\nLast updated: {ts}"
        with open(_CLOUD_TXT_PATH, "rb") as f:
            sent_msg = await bot.send_document(
                chat_id=chat,
                document=f,
                filename="bot_storage.txt",
                caption=caption,
            )
        new_msg_id = sent_msg.message_id

        try:
            await bot.pin_chat_message(
                chat_id=chat,
                message_id=new_msg_id,
                disable_notification=True,
            )
        except Exception as pin_err:
            log_cloud.warning("Could not pin storage message: %s", pin_err)

        return new_msg_id

    except Exception as e:
        log_cloud.error("Cloud txt upload failed: %s", e)
        return msg_id  # return old ID so we don't lose it
    finally:
        try:
            if os.path.exists(_CLOUD_TXT_PATH):
                os.remove(_CLOUD_TXT_PATH)
        except Exception:
            pass


async def save_state(bot=None) -> bool:
    """
    Serialise the full database and push it to the Telegram storage channel.
    Returns True on success.

    Can be called with an explicit bot object, or will use the stored reference.
    """
    global _cloud_storage_msg_id, _cloud_bot_ref

    b = bot or _cloud_bot_ref
    if b is None:
        log_cloud.warning("save_state called but no bot reference available yet.")
        return False

    global _cloud_lock
    if _cloud_lock is None:
        _cloud_lock = asyncio.Lock()

    async with _cloud_lock:
        try:
            data    = _load()
            payload = _cloud_serialise(data)

            new_id = await _cloud_upload_txt_file(b, payload, _cloud_storage_msg_id)
            if new_id:
                _cloud_storage_msg_id = new_id

            user_count = len(data.get("users", {}))
            log_cloud.info("☁️  Cloud save OK (txt file) — %d users, msg_id=%s", user_count, new_id)
            return True

        except Exception as e:
            log_cloud.error("save_state error: %s", e)
            return False


async def _send_cloud_backup(bot) -> bool:
    try:
        data    = _load()
        payload = _cloud_serialise(data)
        ts      = _now_ist().strftime("%Y-%m-%d %H:%M IST")
        caption = f"{CLOUD_BACKUP_TAG}\nBACKUP {ts}"
        backup_txt_path = os.path.join(BASE_DIR, ".cloud_backup_upload.txt")
        try:
            with open(backup_txt_path, "w", encoding="utf-8") as f:
                f.write(payload)
            with open(backup_txt_path, "rb") as f:
                await bot.send_document(
                    chat_id=CLOUD_STORAGE_CHAT_ID,
                    document=f,
                    filename=f"bot_backup_{_now_ist().strftime('%Y%m%d_%H%M')}.txt",
                    caption=caption,
                )
        finally:
            try:
                if os.path.exists(backup_txt_path):
                    os.remove(backup_txt_path)
            except Exception:
                pass
        log_cloud.info("☁️  Cloud backup txt sent at %s", ts)
        return True
    except Exception as e:
        log_cloud.error("Cloud backup error: %s", e)
        return False


#  FULL ZIP BACKUP / RESTORE  (admin panel — "Generate Backup" / "Upload Backup")
#
# Generate Backup: packs every owner's bot files + their profile details into
# separate per-owner folders inside one .zip, plus a full db_snapshot.json for
# 100% fidelity restore. Sent straight to the admin as a document.
#
# Upload Backup: admin sends that .zip back (any time, any host) and every
# bot file + owner record is put back and re-linked to its original owner id.

def _create_full_backup_zip_sync() -> Tuple[str, dict]:
    """
    Builds <owner_id>_<name>/owner_details.json + bot_files/ + bot_data/ +
    hosted_bot_users/ for every PAID (non-free plan) user, plus a root-level
    db_snapshot.json, then zips it all up. Free-plan users are excluded.

    Three separate on-disk sources are pulled per bot so a restore leaves
    every bot exactly as it was, with zero data loss:
      - HOSTED_FILES_DIR/<uid>              -> bot_files/         (uploaded source)
      - BOT_DATA_DIR/<uid>/<bid>            -> bot_data/<bid>/    (LIVE runtime
        workspace -- this is the bot's actual cwd while running, so its own
        databases, sqlite files, login/session files, JSON state, caches,
        anything it writes to disk while running lives HERE, not in
        bot_files/)
      - HOSTED_BOT_USERS_DIR/<bot-key>.json -> hosted_bot_users/<bid>.json
        (the list of end-users who've /start'd that hosted bot)

    Runs in a worker thread (blocking I/O) -- call via asyncio.to_thread.
    Returns (zip_path, stats).
    """
    d = _load()
    users = d.get("users", {})
    bots  = d.get("bots", {})

    tmp_root = os.path.join(BASE_DIR, f".backup_build_{uuid.uuid4().hex}")
    os.makedirs(tmp_root, exist_ok=True)

    owners_included = 0
    bots_included   = 0
    files_included  = 0

    def _copy_tree_everything(src_dir: str, dst_dir: str) -> int:
        """Copy every file under src_dir into dst_dir, skipping only
        __pycache__ (regenerable bytecode cache, never real data).
        Returns count of files copied."""
        n = 0
        for _root, _dirs, _fnames in os.walk(src_dir):
            _dirs[:] = [dn for dn in _dirs if dn != "__pycache__"]
            for _fname in _fnames:
                _src_path = os.path.join(_root, _fname)
                _rel_path = os.path.relpath(_src_path, src_dir)
                _dst_path = os.path.join(dst_dir, _rel_path)
                os.makedirs(os.path.dirname(_dst_path), exist_ok=True)
                shutil.copy2(_src_path, _dst_path)
                n += 1
        return n

    try:
        for uid_s, u in users.items():
            owner_bids = [b for b in u.get("bots", []) if b in bots]

            # Skip anyone who isn't actually hosting a bot -- a backup is for
            # hosted bots + their owners, not every registered/idle user.
            if not owner_bids:
                continue

            # Paid users only -- free-plan users are excluded from the backup.
            if u.get("plan", "free") == "free":
                continue

            uname = safe_filename(u.get("username") or u.get("first_name") or "owner")
            folder_name = f"{uid_s}_{uname}"
            owner_dir = os.path.join(tmp_root, folder_name)
            os.makedirs(owner_dir, exist_ok=True)

            owner_details = {
                "user_id":           u.get("user_id", int(uid_s)),
                "username":          u.get("username", ""),
                "first_name":        u.get("first_name", ""),
                "plan":              u.get("plan", "free"),
                "expiry":            u.get("expiry"),
                "approval_override": u.get("approval_override"),
                "bot_ids":           owner_bids,
                "bots":              {bid: bots[bid] for bid in owner_bids},
            }
            with open(os.path.join(owner_dir, "owner_details.json"), "w", encoding="utf-8") as f:
                json.dump(owner_details, f, indent=2, ensure_ascii=False, default=str)

            # 1) Uploaded source files -- full contents, not just .py, so any
            #    file the owner uploaded alongside the script comes back too.
            src_files_dir = os.path.join(HOSTED_FILES_DIR, uid_s)
            if os.path.isdir(src_files_dir):
                dest_files_dir = os.path.join(owner_dir, "bot_files")
                files_included += _copy_tree_everything(src_files_dir, dest_files_dir)

            # 2) LIVE runtime data per bot -- the bot's actual cwd while it's
            #    running. This is where its own db/sqlite/session/json state
            #    actually lives, so without this a restore would bring the
            #    bot's *code* back but wipe everything it had learned/stored.
            for bid in owner_bids:
                bot_data_src = os.path.join(BOT_DATA_DIR, uid_s, bid)
                if os.path.isdir(bot_data_src):
                    bot_data_dst = os.path.join(owner_dir, "bot_data", bid)
                    files_included += _copy_tree_everything(bot_data_src, bot_data_dst)

            # 3) Per-bot end-user lists (people who /start'd each hosted bot),
            #    stored keyed by the bot's numeric ID (part of the token).
            hbu_dir = os.path.join(owner_dir, "hosted_bot_users")
            for bid in owner_bids:
                tok = bots[bid].get("token", "")
                key = _bot_key_from_token(tok)
                if not key:
                    continue
                hbu_src = os.path.join(HOSTED_BOT_USERS_DIR, f"{key}.json")
                if os.path.isfile(hbu_src):
                    os.makedirs(hbu_dir, exist_ok=True)
                    # Named by bid (stable even if the token ever changes)
                    # rather than by the raw token-derived key.
                    shutil.copy2(hbu_src, os.path.join(hbu_dir, f"{bid}.json"))
                    files_included += 1

            owners_included += 1
            bots_included   += len(owner_bids)

        # Full DB snapshot so settings/bans/plans/payment_pending survive too
        with open(os.path.join(tmp_root, "db_snapshot.json"), "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2, ensure_ascii=False, default=str)

        os.makedirs(BACKUP_DIR, exist_ok=True)
        ts = _now_ist().strftime("%Y%m%d_%H%M%S")
        zip_base = os.path.join(BACKUP_DIR, f"full_backup_{ts}")
        zip_path = shutil.make_archive(zip_base, "zip", tmp_root)

        stats = {
            "owners": owners_included,
            "bots":   bots_included,
            "files":  files_included,
            "size":   os.path.getsize(zip_path),
        }
        return zip_path, stats
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


def _restore_full_backup_zip_sync(zip_path: str) -> dict:
    """
    Extracts a zip built by _create_full_backup_zip_sync, merges db_snapshot.json
    into the live DB (existing users keep the better plan), and restores every
    owner's bot back to full working order:
      • uploaded source          -> HOSTED_FILES_DIR/<uid>
      • live runtime data        -> BOT_DATA_DIR/<uid>/<bid>   (db/sqlite/
        session/json state — merged back exactly as it was so nothing the
        bot had stored is lost)
      • hosted-bot end-user list -> HOSTED_BOT_USERS_DIR/<key>.json (merged,
        never overwritten, so re-restoring an old backup can't erase users
        recorded since)
    Runs in a worker thread — call via asyncio.to_thread.
    Returns stats dict.
    """
    tmp_root = os.path.join(BASE_DIR, f".backup_restore_{uuid.uuid4().hex}")
    os.makedirs(tmp_root, exist_ok=True)

    stats = {"owners": 0, "bots": 0, "files": 0, "errors": 0}

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(tmp_root)

        _PLAN_TIER = ["free", "baby", "basic", "premium", "god", "ultimate", "lifetime"]

        def _plan_rank(plan: str) -> int:
            try:
                return _PLAN_TIER.index(plan)
            except ValueError:
                return 0

        d = _load()

        # 1) Merge the full db snapshot first (users, bots, bans, settings…)
        snap_path = os.path.join(tmp_root, "db_snapshot.json")
        if os.path.isfile(snap_path):
            try:
                with open(snap_path, "r", encoding="utf-8") as f:
                    snap = json.load(f)
            except Exception:
                snap = None

            if snap:
                for bid, b in snap.get("bots", {}).items():
                    d["bots"][bid] = b

                for uid_s, bu in snap.get("users", {}).items():
                    existing = d["users"].get(uid_s)
                    if existing is None:
                        d["users"][uid_s] = bu
                    else:
                        for field in ("username", "first_name"):
                            v = bu.get(field, "")
                            if v:
                                existing[field] = v
                        cur_rank  = _plan_rank(existing.get("plan", "free"))
                        back_rank = _plan_rank(bu.get("plan", "free"))
                        if back_rank > cur_rank:
                            existing["plan"]   = bu.get("plan", "free")
                            existing["expiry"] = bu.get("expiry")
                        existing_bots = set(existing.get("bots", []))
                        existing_bots.update(bu.get("bots", []))
                        existing["bots"] = list(existing_bots)

                for b in snap.get("bans", []):
                    if str(b) not in {str(x) for x in d.get("bans", [])}:
                        d["bans"].append(str(b))

        # 2) Walk owner folders — restore files + re-link bots to owner ids
        for entry in sorted(os.listdir(tmp_root)):
            entry_path = os.path.join(tmp_root, entry)
            if not os.path.isdir(entry_path):
                continue
            m = re.match(r"^(-?\d+)_", entry)
            if not m:
                continue
            uid_s = m.group(1)

            details_path = os.path.join(entry_path, "owner_details.json")
            if os.path.isfile(details_path):
                try:
                    with open(details_path, "r", encoding="utf-8") as f:
                        details = json.load(f)
                except Exception:
                    details = {}

                existing = d["users"].get(uid_s)
                if existing is None:
                    d["users"][uid_s] = {
                        "user_id":           details.get("user_id", int(uid_s)),
                        "username":          details.get("username", ""),
                        "first_name":        details.get("first_name", ""),
                        "plan":              details.get("plan", "free"),
                        "expiry":            details.get("expiry"),
                        "bots":              details.get("bot_ids", []),
                        "approval_override": details.get("approval_override"),
                    }
                    existing = d["users"][uid_s]
                else:
                    cur_bots = set(existing.get("bots", []))
                    cur_bots.update(details.get("bot_ids", []))
                    existing["bots"] = list(cur_bots)

                for bid, b in details.get("bots", {}).items():
                    d["bots"][bid] = b
                    stats["bots"] += 1

            src_files_dir = os.path.join(entry_path, "bot_files")
            if os.path.isdir(src_files_dir):
                dest_files_dir = os.path.join(HOSTED_FILES_DIR, uid_s)
                os.makedirs(dest_files_dir, exist_ok=True)
                for item in os.listdir(src_files_dir):
                    s = os.path.join(src_files_dir, item)
                    dst = os.path.join(dest_files_dir, item)
                    try:
                        if os.path.isdir(s):
                            shutil.copytree(s, dst, dirs_exist_ok=True)
                        else:
                            shutil.copy2(s, dst)
                        for _r, _dd, _fnames in os.walk(s) if os.path.isdir(s) else []:
                            stats["files"] += len(_fnames)
                        if os.path.isfile(s):
                            stats["files"] += 1
                    except Exception:
                        stats["errors"] += 1

            # Restore each bot's LIVE runtime workspace (its own db/sqlite/
            # session/json state) back into BOT_DATA_DIR/<uid>/<bid>/ — this
            # is what the bot process actually reads/writes from at runtime,
            # so without this step a restore would bring the bot's code back
            # but lose everything it had stored while running.
            src_data_dir = os.path.join(entry_path, "bot_data")
            if os.path.isdir(src_data_dir):
                for bid in os.listdir(src_data_dir):
                    s = os.path.join(src_data_dir, bid)
                    if not os.path.isdir(s):
                        continue
                    dst = os.path.join(BOT_DATA_DIR, uid_s, bid)
                    try:
                        os.makedirs(dst, exist_ok=True)
                        shutil.copytree(s, dst, dirs_exist_ok=True)
                        for _r, _dd, _fnames in os.walk(s):
                            stats["files"] += len(_fnames)
                    except Exception:
                        stats["errors"] += 1

            # Restore per-bot end-user lists (people who /start'd each
            # hosted bot). These are keyed on disk by the bot's numeric ID
            # (derived from its token), not by bid, so re-derive that key
            # from the token now stored in d["bots"][bid].
            src_hbu_dir = os.path.join(entry_path, "hosted_bot_users")
            if os.path.isdir(src_hbu_dir):
                os.makedirs(HOSTED_BOT_USERS_DIR, exist_ok=True)
                for fname in os.listdir(src_hbu_dir):
                    if not fname.endswith(".json"):
                        continue
                    bid = fname[:-5]
                    tok = d.get("bots", {}).get(bid, {}).get("token", "")
                    key = _bot_key_from_token(tok) or bid
                    s = os.path.join(src_hbu_dir, fname)
                    dst = os.path.join(HOSTED_BOT_USERS_DIR, f"{key}.json")
                    try:
                        if os.path.isfile(dst):
                            # Merge rather than overwrite so re-restoring
                            # never drops end-users already recorded live.
                            with open(s, "r", encoding="utf-8") as f:
                                incoming = {str(x) for x in json.load(f)}
                            with open(dst, "r", encoding="utf-8") as f:
                                existing_ids = {str(x) for x in json.load(f)}
                            merged = list(existing_ids | incoming)
                            with open(dst, "w", encoding="utf-8") as f:
                                json.dump(merged, f)
                        else:
                            shutil.copy2(s, dst)
                        stats["files"] += 1
                    except Exception:
                        stats["errors"] += 1

            stats["owners"] += 1

        _save(d)
        return stats
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


async def load_state(bot) -> bool:
    """
    Read the pinned DOCUMENT from the storage channel, download the txt file,
    and restore all user data from it.
    Falls back to scanning recent updates for a document with #BOT_STORAGE caption.
    Returns True if data was successfully restored.
    """
    global _cloud_storage_msg_id, _cloud_bot_ref
    _cloud_bot_ref = bot

    global _cloud_lock
    if _cloud_lock is None:
        _cloud_lock = asyncio.Lock()

    log_cloud.debug("Loading state from Telegram cloud storage (txt file)…")

    payload_str: Optional[str] = None
    source_msg_id: Optional[int] = None

    async def _download_file_id(file_id: str) -> Optional[str]:
        tmp_path = os.path.join(BASE_DIR, f".cloud_dl_{uuid.uuid4().hex}.txt")
        try:
            tg_file = await bot.get_file(file_id)
            await tg_file.download_to_drive(tmp_path)
            with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as e:
            log_cloud.warning("Failed to download cloud file: %s", e)
            return None
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

    # If the bot isn't even a member of the backup group/channel, every fallback
    # below (getUpdates scan, then walking ~400 message IDs one by one) is
    # guaranteed to fail too — so don't burn minutes on it. Detect that up
    # front and, if so, start a fresh database on this host immediately.
    bot_in_backup_group = True
    try:
        chat = await bot.get_chat(CLOUD_STORAGE_CHAT_ID)
        pinned = getattr(chat, "pinned_message", None)
        if pinned:
            caption = (pinned.caption or "").strip()
            doc = getattr(pinned, "document", None)
            if doc and CLOUD_STORAGE_TAG in caption:
                content = await _download_file_id(doc.file_id)
                if content:
                    payload_str   = content
                    source_msg_id = pinned.message_id
                    log_cloud.debug("Found pinned storage document id=%d", source_msg_id)
    except (BadRequest, Forbidden) as e:
        msg = str(e).lower()
        not_a_member = any(x in msg for x in (
            "chat not found", "bot is not a member", "not enough rights",
            "have no rights", "kicked", "user not found",
        ))
        if not_a_member:
            bot_in_backup_group = False
            log_cloud.warning(
                "☁️  Bot is NOT in the backup group (CLOUD_STORAGE_CHAT_ID=%s): %s — "
                "skipping slow fallback scan, starting a fresh database.",
                CLOUD_STORAGE_CHAT_ID, e,
            )
        else:
            log_cloud.warning("Could not read pinned message: %s", e)
    except Exception as e:
        log_cloud.warning("Could not read pinned message: %s", e)

    if not payload_str and not bot_in_backup_group:
        log_cloud.warning("☁️  Skipping backup restore — bot not in backup group. Starting fresh.")
        return False

    # updates in getUpdates. We scan ALL pending updates for any storage doc.
    if not payload_str:
        log_cloud.info("☁️  Scanning getUpdates for channel posts (storage/backup docs)...")
        try:
            both_tags = (CLOUD_STORAGE_TAG, CLOUD_BACKUP_TAG)
            url = f"https://api.telegram.org/bot{Bot_token}/getUpdates?limit=100&timeout=0"
            req = _urlreq.Request(url)
            with _urlreq.urlopen(req, timeout=20) as r:
                result = json.loads(r.read().decode())
            if result.get("ok"):
                updates = list(reversed(result.get("result", [])))
                for upd in updates:
                    msg = upd.get("channel_post") or upd.get("message")
                    if not msg:
                        continue
                    chat_id_upd = str(msg.get("chat", {}).get("id", ""))
                    if chat_id_upd != str(CLOUD_STORAGE_CHAT_ID):
                        continue
                    caption = (msg.get("caption") or "").strip()
                    doc = msg.get("document")
                    if doc and any(tag in caption for tag in both_tags):
                        content = await _download_file_id(doc["file_id"])
                        if content:
                            payload_str   = content
                            source_msg_id = msg.get("message_id")
                            tag_found = CLOUD_BACKUP_TAG if CLOUD_BACKUP_TAG in caption else CLOUD_STORAGE_TAG
                            log_cloud.info("☁️  Found %s via getUpdates msg_id=%s", tag_found, source_msg_id)
                            break
        except Exception as e:
            log_cloud.warning("getUpdates channel scan failed: %s", e)

    if not payload_str:
        log_cloud.info("☁️  Walking channel message IDs for backup doc...")
        try:
            both_tags = (CLOUD_STORAGE_TAG, CLOUD_BACKUP_TAG)
            chat_id = CLOUD_STORAGE_CHAT_ID

            start_id = 1
            try:
                ch_info = await bot.get_chat(chat_id)
                pm2 = getattr(ch_info, "pinned_message", None)
                if pm2 and pm2.message_id:
                    start_id = pm2.message_id + 50   # scan ahead of pinned
                else:
                    start_id = 500   # safe default for newer channels
            except Exception:
                start_id = 500

            found_doc = None
            found_mid = None

            for mid in range(start_id, max(start_id - 400, 0), -1):
                try:
                    params = _urlparse.urlencode({
                        "chat_id":      chat_id,
                        "from_chat_id": chat_id,
                        "message_id":   mid,
                    })
                    url = f"https://api.telegram.org/bot{Bot_token}/copyMessage?{params}"
                    req = _urlreq.Request(url)
                    with _urlreq.urlopen(req, timeout=6) as r:
                        res = json.loads(r.read().decode())

                    if not res.get("ok"):
                        continue

                    # just to inspect (forward to the SAME channel, delete immediately)
                    params2 = _urlparse.urlencode({
                        "chat_id":      chat_id,
                        "from_chat_id": chat_id,
                        "message_id":   mid,
                        "disable_notification": "true",
                    })
                    url2 = f"https://api.telegram.org/bot{Bot_token}/forwardMessage?{params2}"
                    req2 = _urlreq.Request(url2)
                    with _urlreq.urlopen(req2, timeout=6) as r2:
                        res2 = json.loads(r2.read().decode())

                    if not res2.get("ok"):
                        continue

                    fwd_msg = res2.get("result", {})
                    caption = (fwd_msg.get("caption") or "").strip()
                    doc = fwd_msg.get("document")

                    fwd_mid = fwd_msg.get("message_id")
                    if fwd_mid:
                        try:
                            del_params = _urlparse.urlencode({
                                "chat_id":    chat_id,
                                "message_id": fwd_mid,
                            })
                            del_url = f"https://api.telegram.org/bot{Bot_token}/deleteMessage?{del_params}"
                            with _urlreq.urlopen(_urlreq.Request(del_url), timeout=5):
                                pass
                        except Exception:
                            pass

                    if doc and any(tag in caption for tag in both_tags):
                        found_doc = doc
                        found_mid = mid
                        tag_found = CLOUD_BACKUP_TAG if CLOUD_BACKUP_TAG in caption else CLOUD_STORAGE_TAG
                        log_cloud.info("☁️  Found %s at channel msg_id=%d", tag_found, mid)
                        break

                except Exception:
                    continue

            if found_doc:
                content = await _download_file_id(found_doc["file_id"])
                if content:
                    payload_str   = content
                    source_msg_id = found_mid

        except Exception as e:
            log_cloud.warning("Channel ID walk failed: %s", e)

    if not payload_str:
        log_cloud.warning("☁️  No cloud storage txt file found. Starting fresh.")
        return False

    restored = _cloud_deserialise(payload_str)
    if not restored:
        log_cloud.error("☁️  Failed to parse cloud storage payload.")
        return False

    with _db_lock:
        blank = _blank_db()
        try:
            if os.path.exists(DB_PATH):
                with open(DB_PATH, "r", encoding="utf-8") as f:
                    local = json.load(f)
            else:
                local = blank
        except Exception:
            local = blank

        # We rebuild the entire "bots" dict from what is physically on disk.
        # This means bots are NEVER lost on restart as long as files exist.
        # Runtime data files (users.json, etc.) live in BOT_DATA_DIR and are
        # NOT scanned here — keeping bot files and data completely separate.
        disk_bots: dict = {}   # bid -> bot record
        if os.path.isdir(HOSTED_FILES_DIR):
            for uid_s in os.listdir(HOSTED_FILES_DIR):
                uid_dir = os.path.join(HOSTED_FILES_DIR, uid_s)
                if not os.path.isdir(uid_dir):
                    continue
                for bid in os.listdir(uid_dir):
                    bid_dir = os.path.join(uid_dir, bid)
                    if not os.path.isdir(bid_dir):
                        continue
                    # (e.g. users.json, config.json) from being assigned to users
                    # on restart in place of the real (possibly encrypted) bot file.
                    found_fp = None
                    display_name = ""
                    prev = local.get("bots", {}).get(bid, {})
                    prev_fname = prev.get("file_name", "")

                    _RUNNABLE_EXTS = (".py",)
                    _STORAGE_EXTS  = (".txt", ".json")
                    _BOT_EXTS      = _RUNNABLE_EXTS + _STORAGE_EXTS

                    if prev_fname:
                        _cand     = os.path.join(bid_dir, prev_fname)
                        _cand_enc = _cand + ".enc"
                        if os.path.isfile(_cand):
                            found_fp     = _cand
                            display_name = prev_fname
                        elif os.path.isfile(_cand_enc):
                            found_fp     = _cand_enc
                            display_name = prev_fname

                    if not found_fp:
                        _run_cands  = []   # .py (runnable)
                        _stor_cands = []   # .txt / .json (storage)
                        _enc_cands  = []   # .enc whose base name has a bot extension
                        for fname in sorted(os.listdir(bid_dir)):
                            fpath = os.path.join(bid_dir, fname)
                            if not os.path.isfile(fpath):
                                continue
                            if fname.endswith(".enc"):
                                _base_ext = os.path.splitext(fname[:-4])[1].lower()
                                if _base_ext in _BOT_EXTS:
                                    _enc_cands.append((fname[:-4], fpath))
                            else:
                                _ext = os.path.splitext(fname)[1].lower()
                                if _ext in _RUNNABLE_EXTS:
                                    _run_cands.append((fname, fpath))
                                elif _ext in _STORAGE_EXTS:
                                    _stor_cands.append((fname, fpath))

                        if _run_cands:
                            display_name, found_fp = _run_cands[0]
                        elif _stor_cands:
                            display_name, found_fp = _stor_cands[0]
                        elif _enc_cands:
                            display_name, found_fp = _enc_cands[0]

                    if not found_fp:
                        continue
                    existing = local.get("bots", {}).get(bid)
                    if existing and existing.get("file_path") == found_fp:
                        disk_bots[bid] = existing
                    else:
                        tok = ""
                        try:
                            readable = found_fp[:-4] if found_fp.endswith(".enc") else found_fp
                            if os.path.exists(readable):
                                raw_tok = extract_bot_token(readable)
                                if raw_tok:
                                    tok = _encrypt_token(raw_tok)
                        except Exception:
                            pass
                        disk_bots[bid] = {
                            "bot_id":       bid,
                            "user_id":      int(uid_s),
                            "file_name":    prev.get("file_name", display_name),
                            "file_path":    found_fp,
                            "status":       "stopped",
                            "pid":          None,
                            "created":      prev.get("created", _now()),
                            "pending":      prev.get("pending", False),
                            "started_at":   None,
                            "bot_token":    prev.get("bot_token", tok),
                            "project_name": prev.get("project_name", ""),
                            "internal_pid": prev.get("internal_pid", 0),
                        }
                        log_cloud.debug("Loaded bot %s (user %s) from disk: %s", bid, uid_s, found_fp)

        log_cloud.debug("Disk scan complete: %d bot file(s) found in hosted_files/", len(disk_bots))

        local["bots"] = disk_bots

        cloud_users = restored.get("users", {})
        local["users"] = cloud_users
        local["bans"]  = restored.get("bans",  local.get("bans", []))
        local["codes"] = restored.get("codes", local.get("codes", {}))

        uid_to_bids: dict = {}
        for bid, brec in disk_bots.items():
            uid_to_bids.setdefault(str(brec["user_id"]), []).append(bid)

        files_found = sum(len(v) for v in uid_to_bids.values())
        if files_found == 0:
            for u in local["users"].values():
                u["bots"] = []
            log_cloud.debug("hosted_files/ is empty — starting fresh with no bots.")
        else:
            for uid_s, u in local["users"].items():
                u["bots"] = uid_to_bids.get(uid_s, [])

        cloud_settings = restored.get("settings", {})
        for k, v in cloud_settings.items():
            if k not in ("payment_qr",):   # payment_qr is a local file path
                local.setdefault("settings", {}).update({k: v})

        _write(local)

    user_count    = len(restored.get("users", {}))
    premium_count = sum(
        1 for u in restored.get("users", {}).values()
        if u.get("plan", "free") not in ("free",)
    )
    ban_count = len(restored.get("bans", []))

    _restore_stats.update({
        "files":   files_found,
        "users":   user_count,
        "premium": premium_count,
        "banned":  ban_count,
    })

    log_cloud.debug("Restored %d users (%d premium, %d banned) from cloud txt file",
                     user_count, premium_count, ban_count)

    _cloud_storage_msg_id = source_msg_id
    return True


_CLOUD_DEBOUNCE_SECS = 5
_cloud_debounce_task: Optional[asyncio.Task] = None

async def _cloud_debounced_save():
    await asyncio.sleep(_CLOUD_DEBOUNCE_SECS)
    await save_state()

def schedule_cloud_save():
    """
    Call this after any DB mutation to trigger a debounced cloud push.
    Safe to call from sync code — schedules a coroutine on the running loop.
    """
    global _cloud_debounce_task
    try:
        loop = asyncio.get_running_loop()
        if _cloud_debounce_task and not _cloud_debounce_task.done():
            _cloud_debounce_task.cancel()
        _cloud_debounce_task = loop.create_task(_cloud_debounced_save())
    except RuntimeError:
        pass  # No running loop yet (startup) — ignore


async def _cloud_hourly_backup(application):
    await asyncio.sleep(60)   # wait 1 min after startup before first backup
    while True:
        try:
            await _send_cloud_backup(application.bot)
        except Exception as e:
            log_cloud.error("Hourly backup error: %s", e)
        await asyncio.sleep(3600)   # every hour


def get_settings() -> dict:
    return _load()["settings"]

def upd_settings(kv: dict):
    d = _load()
    d["settings"].update(kv)
    _save(d)

def get_setting(key, default=None):
    return _load()["settings"].get(key, default)

def get_force_join_channels() -> list:
    """Return merged list: hardcoded channels first, then admin-added ones.
    Each item: {"title": str, "username": "@ch", "link": "url"}"""
    merged = []
    seen = set()
    for ch in HARDCODED_FJ_CHANNELS:
        uname = ch.get("username", "").lower()
        if uname and uname not in seen:
            merged.append(dict(ch))
            seen.add(uname)
    db_channels = get_setting("force_join_channels", [])
    if isinstance(db_channels, list):
        for ch in db_channels:
            uname = ch.get("username", "").lower()
            if uname and uname not in seen:
                entry = dict(ch)
                entry.setdefault("title", ch.get("username", "Channel"))
                merged.append(entry)
                seen.add(uname)
    return merged

def add_force_join_channel(username: str, link: str):
    add_force_join_channel_with_title(username, link, username)

def add_force_join_channel_with_title(username: str, link: str, title: str):
    d = _load()
    channels = d["settings"].setdefault("force_join_channels", [])
    for ch in channels:
        if ch.get("username", "").lower() == username.lower():
            ch["link"] = link
            ch["title"] = title
            _save(d)
            return
    channels.append({"username": username, "link": link, "title": title})
    _save(d)

def remove_force_join_channel(index: int):
    """Remove a channel from the admin-added list (NOT from hardcoded channels)."""
    d = _load()
    channels = d["settings"].get("force_join_channels", [])
    if 0 <= index < len(channels):
        channels.pop(index)
    d["settings"]["force_join_channels"] = channels
    _save(d)


def ensure_user(uid: int, username: str = "", first_name: str = "") -> dict:
    d = _load()
    k = str(uid)
    if k not in d["users"]:
        d["users"][k] = {
            "user_id": uid, "username": username, "first_name": first_name,
            "plan": "free", "expiry": None, "bots": [],
            "approval_override": None,
            "member_since": _now_ist().strftime("%d-%m-%Y"),
        }
        _save(d)
    else:
        changed = False
        u = d["users"][k]
        for field, val in [("username", username), ("first_name", first_name)]:
            if val and u.get(field) != val:
                u[field] = val
                changed = True
        for field, val in [("plan","free"),("expiry",None),("bots",[]),("approval_override",None)]:
            if field not in u:
                u[field] = val
                changed = True
        for legacy in ("joined",):
            if legacy in u:
                del u[legacy]
                changed = True
        if changed:
            _save(d)
    return d["users"][k]

def get_user(uid: int) -> Optional[dict]:
    return _load()["users"].get(str(uid))

def upd_user(uid: int, kv: dict):
    d = _load()
    k = str(uid)
    if k in d["users"]:
        d["users"][k].update(kv)
        _save(d)

def all_users() -> dict:
    return _load()["users"]

def check_expiry(uid: int):
    u = get_user(uid)
    if u and u.get("plan","free") not in ("free", "lifetime") and u.get("expiry"):
        try:
            # the plan at 00:00:01 on the expiry day, robbing the user of the day.
            if _now_ist().date() > _parse_dt(u["expiry"]).date():
                upd_user(uid, {"plan": "free", "expiry": None})
        except Exception:
            pass

def is_banned(uid: int) -> bool:
    return str(uid) in [str(b) for b in _load().get("bans", [])]

def ban_user(uid: int):
    d = _load()
    bans = [str(b) for b in d.get("bans", [])]
    if str(uid) not in bans:
        bans.append(str(uid))
    d["bans"] = bans
    _save(d)

def unban_user(uid: int):
    d = _load()
    d["bans"] = [str(b) for b in d.get("bans", []) if str(b) != str(uid)]
    _save(d)

def get_file_limit(uid: int) -> int:
    check_expiry(uid)
    u = get_user(uid)
    plan = u.get("plan","free") if u else "free"
    if plan not in PLANS:
        plan = "free"
    lim = PLANS[plan]["file_limit"]
    if lim == UNLIMITED_SENTINEL:
        return 999999  # effectively unlimited
    return lim

def get_run_limit(uid: int) -> int:
    check_expiry(uid)
    u = get_user(uid)
    plan = u.get("plan","free") if u else "free"
    if plan not in PLANS:
        plan = "free"
    lim = PLANS[plan]["run_limit"]
    if lim == UNLIMITED_SENTINEL:
        return 999999
    return lim

def is_unlimited(uid: int) -> bool:
    check_expiry(uid)
    u = get_user(uid)
    plan = u.get("plan","free") if u else "free"
    return PLANS.get(plan, {}).get("file_limit", 0) == UNLIMITED_SENTINEL

def get_ram_limit_mb(uid: int):
    """RAM ceiling (MB) for a user's plan, enforced per hosted bot.
    Returns None for unlimited plans (no cap to enforce).
    An admin-assigned custom_ram_mb override on the user record takes
    priority over the plan's ram_mb, on any plan including free."""
    check_expiry(uid)
    u = get_user(uid)
    custom = (u or {}).get("custom_ram_mb")
    if custom is not None:
        if custom == UNLIMITED_SENTINEL:
            return None
        return custom
    plan = u.get("plan","free") if u else "free"
    if plan not in PLANS:
        plan = "free"
    lim = PLANS[plan].get("ram_mb", PLANS["free"]["ram_mb"])
    if lim == UNLIMITED_SENTINEL:
        return None
    return lim

def bot_count(uid: int) -> int:
    """Count only bots that actually exist in the bots dict.
    Stale bot IDs restored from cloud (no matching bot record) are ignored
    so they don't block the user's file/slot quota on a fresh hosting."""
    d = _load()
    u = d["users"].get(str(uid))
    if not u:
        return 0
    return sum(1 for bid in u.get("bots", []) if bid in d["bots"])

def running_bot_count(uid: int) -> int:
    sync_statuses()
    return sum(1 for b in user_bots(uid) if b.get("status") == "running")

def give_subscription(uid: int, plan: str, days: int):
    if plan not in PLANS:
        plan = "free"
    if plan == "lifetime":
        expiry = None
    elif plan == "free" or days <= 0:
        expiry = None
    else:
        expiry = (_now_ist() + timedelta(days=days)).strftime("%d-%m-%Y")
    upd_user(uid, {"plan": plan, "expiry": expiry})

def needs_approval(uid: int) -> bool:
    u = get_user(uid)
    override = u.get("approval_override") if u else None
    if override is not None:
        return bool(override)
    if not get_setting("approval_required_all", True):
        return False
    plan = u.get("plan","free") if u else "free"
    if plan not in PLANS:
        plan = "free"
    return PLANS[plan].get("needs_approval", True)


def _next_internal_pid(uid: int) -> int:
    d = _load()
    k = str(uid)
    user_bids = d["users"].get(k, {}).get("bots", [])
    existing = [
        d["bots"][b].get("internal_pid", 0)
        for b in user_bids
        if b in d["bots"]
    ]
    return (max(existing) + 1) if existing else 1

def add_bot(uid: int, bid: str, name: str, path: str, pending: bool = False, bot_token: str = "", project_name: str = ""):
    d = _load()
    k = str(uid)
    user_bids = d["users"].get(k, {}).get("bots", [])
    existing_pids = [
        d["bots"][b].get("internal_pid", 0)
        for b in user_bids
        if b in d["bots"]
    ]
    internal_pid = (max(existing_pids) + 1) if existing_pids else 1
    d["bots"][bid] = {
        "bot_id": bid, "user_id": uid,
        "file_name": name, "file_path": path,
        "status": "stopped", "pid": None, "created": _now(),
        "pending": pending, "started_at": None,
        "bot_token": _encrypt_token(bot_token) if bot_token else "",
        "project_name": project_name,
        "internal_pid": internal_pid,
    }
    if k in d["users"] and bid not in d["users"][k].get("bots",[]):
        d["users"][k].setdefault("bots",[]).append(bid)
    _save(d)

def get_bot(bid: str) -> Optional[dict]:
    return _load()["bots"].get(bid)

def user_bots(uid: int) -> list:
    d = _load()
    k = str(uid)
    return [d["bots"][b] for b in d["users"].get(k,{}).get("bots",[]) if b in d["bots"]]

def all_bots() -> dict:
    return _load()["bots"]

def upd_bot(bid: str, kv: dict):
    d = _load()
    if bid in d["bots"]:
        d["bots"][bid].update(kv)
        _save(d)

def del_bot(bid: str):
    d = _load()
    b = d["bots"].get(bid)
    if b:
        k = str(b["user_id"])
        bots = d["users"].get(k,{}).get("bots",[])
        if bid in bots:
            bots.remove(bid)
        if k in d["users"]:
            d["users"][k]["bots"] = bots
        del d["bots"][bid]
        _save(d)

def transfer_bot_ownership(bid: str, new_uid: int) -> Tuple[bool, str]:
    """Transfer bot from current owner to new_uid."""
    d = _load()
    b = d["bots"].get(bid)
    if not b:
        return False, "Bot not found."
    old_uid_s = str(b["user_id"])
    new_uid_s = str(new_uid)
    if old_uid_s == new_uid_s:
        return False, "Already owned by this user."
    if new_uid_s not in d["users"]:
        return False, f"User {new_uid} not found in database."
    if old_uid_s in d["users"]:
        old_bots = d["users"][old_uid_s].get("bots", [])
        if bid in old_bots:
            old_bots.remove(bid)
        d["users"][old_uid_s]["bots"] = old_bots
    new_bots = d["users"][new_uid_s].get("bots", [])
    if bid not in new_bots:
        new_bots.append(bid)
    d["users"][new_uid_s]["bots"] = new_bots
    d["bots"][bid]["user_id"] = new_uid
    _save(d)
    return True, f"Bot transferred to user {new_uid}."


def save_code(code: str, plan: str, days: int, max_uses: int = 1):
    d = _load()
    d["codes"][code.upper()] = {
        "code": code.upper(), "plan": plan, "days": days,
        "uses": 0, "max_uses": max_uses,
        "used": False, "used_by": [], "created": _now(),
    }
    _save(d)

def code_exists(code: str) -> bool:
    return code.upper() in _load()["codes"]

def use_code(code: str, uid: int) -> Tuple[bool, str]:
    d = _load()
    c = d["codes"].get(code.upper())
    if not c:
        return False, "❌ <b>Invalid code.</b> Check and try again."
    max_uses = c.get("max_uses", 1)
    uses = c.get("uses", 0)
    if uses >= max_uses:
        return False, "❌ <b>This code has reached its usage limit.</b>"
    if str(uid) in [str(x) for x in c.get("used_by", [])]:
        return False, "❌ <b>You already redeemed this code.</b>"
    plan = c.get("plan","free")
    if plan not in PLANS:
        plan = "free"
    if plan == "lifetime":
        expiry = None
    else:
        expiry = (_now_ist() + timedelta(days=c["days"])).strftime("%d-%m-%Y")
    k = str(uid)
    if k in d["users"]:
        d["users"][k]["plan"]   = plan
        d["users"][k]["expiry"] = expiry
    c.setdefault("used_by",[]).append(uid)
    c["uses"] = uses + 1
    if c["uses"] >= max_uses:
        c["used"] = True
    _save(d)
    p = PLANS[plan]
    file_limit_display = "Unlimited ♾️" if p["file_limit"] == UNLIMITED_SENTINEL else str(p["file_limit"])
    ram_display = "Unlimited ♾️" if p.get("ram_mb", 0) == UNLIMITED_SENTINEL else f"{p.get('ram_mb', 0)} MB"
    duration_display = "Lifetime ♾️" if plan == "lifetime" else f"{c['days']} days"
    return True, (
        f"✅ <b>Code Redeemed Successfully!</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"{p['emoji']} <b>Plan:</b>     <b>{p['name']}</b>\n"
        f"📁 <b>Files:</b>    <b>{file_limit_display}</b>\n"
        f"🧠 <b>RAM:</b>      <b>{ram_display}</b>\n"
        f"📅 <b>Duration:</b> <b>{duration_display}</b>"
    )

def all_codes() -> dict:
    return _load()["codes"]


def get_stats() -> dict:
    d = _load()
    running = sum(1 for b in d["bots"].values() if b.get("status") == "running")
    premium = sum(1 for u in d["users"].values() if u.get("plan", "free") != "free")
    return {"users": len(d["users"]), "bots": len(d["bots"]), "running": running, "premium": premium}


def save_broadcast(broadcast_id: str, preview: str, sent_map: dict, failed_map: dict = None):
    d = _load()
    d.setdefault("broadcasts",[])
    rec = {"id": broadcast_id, "preview": preview[:80], "sent_at": _now(), "sent_map": sent_map}
    if failed_map:
        rec["failed_map"] = failed_map
    d["broadcasts"].append(rec)
    d["broadcasts"] = d["broadcasts"][-20:]
    _save(d)

def all_broadcasts() -> list:
    return _load().get("broadcasts", [])

def get_broadcast(broadcast_id: str) -> Optional[dict]:
    for b in _load().get("broadcasts", []):
        if b["id"] == broadcast_id:
            return b
    return None

def del_broadcast_record(broadcast_id: str):
    d = _load()
    d["broadcasts"] = [b for b in d.get("broadcasts",[]) if b["id"] != broadcast_id]
    _save(d)

def del_user(uid: int):
    """Remove a user from the main users DB and ban list."""
    d = _load()
    uid_s = str(uid)
    d["users"].pop(uid_s, None)
    d["bans"] = [b for b in d.get("bans", []) if str(b) != uid_s]
    _save(d)


def save_custom_message(msg_id: str, preview: str, chat_map: dict):
    d = _load()
    d.setdefault("custom_messages",[])
    d["custom_messages"].append({"id": msg_id, "preview": preview[:80], "sent_at": _now(), "chat_map": chat_map})
    d["custom_messages"] = d["custom_messages"][-20:]
    _save(d)

def all_custom_messages() -> list:
    return _load().get("custom_messages", [])

def get_custom_message(msg_id: str) -> Optional[dict]:
    for m in _load().get("custom_messages",[]):
        if m["id"] == msg_id:
            return m
    return None

def del_custom_message_record(msg_id: str):
    d = _load()
    d["custom_messages"] = [m for m in d.get("custom_messages",[]) if m["id"] != msg_id]
    _save(d)


def _bot_key_from_token(token: str) -> str:
    if not token or ":" not in token:
        return ""
    return token.split(":",1)[0].strip()

def _hbu_path(token: str) -> str:
    """Return the path to the per-bot user-list file in HOSTED_BOT_USERS_DIR.

    Each hosted bot gets its own JSON file keyed by the numeric bot-ID
    (the part before ':' in the token), which is stable and unique per bot.
    Separating these files from hosting_data.json means:
      • Hosting-bot users  (people who /start the HOSTING bot)  → hosting_data.json → d["users"]
      • Hosted-bot users   (people who /start each HOSTED bot)  → hosted_bot_users/<id>.json
    No mixing, no growing the central DB with millions of end-user IDs.
    """
    key = _bot_key_from_token(token) or "unknown"
    return os.path.join(HOSTED_BOT_USERS_DIR, f"{key}.json")

def _hbu_migrate_from_db() -> None:
    try:
        d = _load()
        old = d.pop("hosted_bot_users", {})
        if not old:
            return
        for key, ids in old.items():
            fpath = os.path.join(HOSTED_BOT_USERS_DIR, f"{key}.json")
            if not os.path.exists(fpath):
                existing: set = set()
            else:
                try:
                    with open(fpath) as f:
                        existing = {str(x) for x in json.load(f)}
                except Exception:
                    existing = set()
            merged = list(existing | {str(x) for x in ids})
            with open(fpath, "w") as f:
                json.dump(merged, f)
        _save(d)
        log.info("Migrated hosted_bot_users → %s (%d bot(s))", HOSTED_BOT_USERS_DIR, len(old))
    except Exception as e:
        log.warning("hosted_bot_users migration failed (non-fatal): %s", e)

def hosted_bot_users_list(token: str) -> list:
    """Return the list of user IDs who have interacted with the given HOSTED bot.

    NOTE: This is entirely separate from all_users() which returns hosting-bot users.
    Hosted-bot user lists are stored per-bot in HOSTED_BOT_USERS_DIR.
    """
    fpath = _hbu_path(token)
    try:
        with open(fpath) as f:
            raw = json.load(f)
        out = []
        for v in raw:
            try:
                out.append(int(v))
            except (TypeError, ValueError):
                continue
        return out
    except FileNotFoundError:
        return []
    except Exception:
        return []

def add_hosted_bot_users_bulk(token: str, user_ids):
    """Add user IDs to this hosted bot's user list (stored in HOSTED_BOT_USERS_DIR).

    Idempotent — duplicate IDs are silently ignored.
    Does NOT touch hosting_data.json or the hosting-bot user table.
    """
    if not token or ":" not in token:
        return
    fpath = _hbu_path(token)
    try:
        try:
            with open(fpath) as f:
                existing = {str(x) for x in json.load(f)}
        except FileNotFoundError:
            existing = set()
        before = len(existing)
        for u in user_ids:
            try:
                existing.add(str(int(u)))
            except (TypeError, ValueError):
                continue
        if len(existing) != before:
            with open(fpath, "w") as f:
                json.dump(list(existing), f)
    except Exception as e:
        log.warning("add_hosted_bot_users_bulk failed for token %s…: %s",
                    token[:8] if token else "?", e)

def add_hosted_bot_user(token: str, user_id: int):
    """Add a single user ID to this hosted bot's user list."""
    add_hosted_bot_users_bulk(token, [user_id])

def _encrypt_token(token: str) -> str:
    try:
        return _FERNET.encrypt(token.encode()).decode()
    except Exception:
        return token  # fallback: store plaintext if encryption fails

def _decrypt_token(raw: str) -> str:
    if not raw:
        return raw
    try:
        return _FERNET.decrypt(raw.encode()).decode()
    except Exception:
        return raw  # plaintext or wrong key — return as-is

def get_decrypted_bot_token(b: dict) -> str:
    """Get and decrypt the bot token from a bot record."""
    raw = b.get("bot_token", "") or ""
    return _decrypt_token(raw)

def store_bot_token_in_db(bid: str, token: str):
    if token:
        upd_bot(bid, {"bot_token": _encrypt_token(token)})


def add_payment_pending(uid: int, plan: str, screenshot_msg_id: int, chat_id: int):
    d = _load()
    d["payment_pending"][str(uid)] = {
        "uid": uid, "plan": plan,
        "screenshot_msg_id": screenshot_msg_id,
        "chat_id": chat_id,
        "created": _now(),
    }
    _save(d)

def get_payment_pending(uid: int) -> Optional[dict]:
    return _load()["payment_pending"].get(str(uid))

def del_payment_pending(uid: int):
    d = _load()
    d["payment_pending"].pop(str(uid), None)
    _save(d)

def all_payment_pending() -> dict:
    return _load().get("payment_pending", {})


_procs: dict = {}
PIP_ERRORS: dict = {}


_RT_FD_WARN_THRESHOLD  = 250    # open file-descriptor count → warning log
_RT_FD_KILL_THRESHOLD  = 450    # open file-descriptor count → kill bot
_RT_SCAN_INTERVAL_SECS = 10     # watchdog poll interval (seconds)

_RT_SENSITIVE_PREFIXES = (
    "/root",
    "/home",
    BASE_DIR,           # The hosting-platform root — note: bot_dir IS inside here,
                        # so the allowed-prefix check runs first and wins.
)

_RT_ALLOWED_PREFIXES = (
    os.path.realpath(BOT_DATA_DIR),     # bot workspaces
    os.path.realpath(PIP_TARGET_DIR),   # pip packages
    os.path.realpath(LOGS_DIR),         # the bot's own inherited stdout/stderr log file
    "/usr",
    "/lib",
    "/lib64",
    "/tmp",
    "/proc/self",
    "/dev",
)

_watchdog_stop: dict = {}

_RT_RESTART_COOLDOWN = 10   # base cooldown (seconds) before the first restart
_RT_MAX_BACKOFF_SECS = 300  # exponential backoff cap: 10 → 20 → 40 → … → 300 s
_RT_RESTART_WINDOW   = 300  # rolling window (seconds); crashes older than this reset the backoff counter

_restart_counts: dict = {}


def _rt_kill_bot(bid: str, pid: int, reason: str) -> None:
    _sec_event("RUNTIME_KILL", reason, filename=bid)
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(os.getpgid(pid), sig)
            break
        except Exception:
            try:
                os.kill(pid, sig)
                break
            except Exception:
                pass
    try:
        upd_bot(bid, {"status": "error", "pid": None})
    except Exception:
        pass
    try:
        lp = _log_path(bid)
        with open(lp, "a", encoding="utf-8") as lf:
            lf.write(
                f"[{_now_ist():%Y-%m-%d %H:%M:%S} IST] "
                f"── [SECURITY WATCHDOG] Bot killed: {reason} ──\n"
            )
    except Exception:
        pass


def _watchdog_thread(
    bid: str,
    pid: int,
    bot_dir: str,
    stop_evt: threading.Event,
    own_hosted_dir: Optional[str] = None,
) -> None:
    """
    Background daemon thread that monitors a running bot process for suspicious
    runtime behaviour and kills it automatically if thresholds are breached.

    Monitored conditions:
      • Excessive open file descriptors (>250 warns, >450 kills)
      • Open files outside the bot's allowed directory tree (kills immediately)
      • Files opened inside sensitive host paths (/root, /home, BASE_DIR)

    `own_hosted_dir`, when given, is THIS bot's own subfolder under
    HOSTED_FILES_DIR (i.e. HOSTED_FILES_DIR/<uid>/<bid>) — never the shared
    HOSTED_FILES_DIR root and never another bot's folder. Some bots resolve
    relative data paths (e.g. "data/bot.db") against the folder their script
    was uploaded to rather than the BOT_DATA_DIR cwd, so that one folder is
    whitelisted in addition to bot_dir — nothing broader.

    The watchdog uses psutil when available for richer data and falls back to
    reading /proc/<pid>/fd via os.listdir (Linux only, no extra deps required).
    """
    real_bot_dir = os.path.realpath(bot_dir)
    allowed = _RT_ALLOWED_PREFIXES + (real_bot_dir,)
    if own_hosted_dir:
        real_own_hosted_dir = os.path.realpath(own_hosted_dir)
        # Guard against a bad/empty join ever whitelisting all of HOSTED_FILES_DIR.
        _real_hosted_root = os.path.realpath(HOSTED_FILES_DIR)
        if real_own_hosted_dir != _real_hosted_root and real_own_hosted_dir.startswith(_real_hosted_root + os.sep):
            allowed = allowed + (real_own_hosted_dir,)

    while not stop_evt.wait(timeout=_RT_SCAN_INTERVAL_SECS):
        try:
            if not _alive(pid):
                # itself triggered the termination (stop_evt already set).
                if not stop_evt.is_set():
                    threading.Thread(
                        target=_auto_restart_bot,
                        args=(bid,),
                        daemon=True,
                        name=f"autorestart-{bid[:8]}",
                    ).start()
                break   # Watchdog thread exits regardless

            try:
                fd_dir = f"/proc/{pid}/fd"
                fd_count = len(os.listdir(fd_dir))
            except (PermissionError, FileNotFoundError, OSError):
                fd_count = 0

            if fd_count >= _RT_FD_KILL_THRESHOLD:
                _sec_event(
                    "RUNTIME_FD_KILL",
                    f"fd_count={fd_count} >= {_RT_FD_KILL_THRESHOLD}",
                    filename=bid,
                )
                _rt_kill_bot(bid, pid, f"excessive open file descriptors ({fd_count})")
                break

            if fd_count >= _RT_FD_WARN_THRESHOLD:
                _sec_event(
                    "RUNTIME_FD_WARN",
                    f"fd_count={fd_count} >= {_RT_FD_WARN_THRESHOLD}",
                    filename=bid,
                )

            if _PSUTIL:
                try:
                    proc = _psutil.Process(pid)
                    open_files = proc.open_files()
                    for of in open_files:
                        fpath = os.path.realpath(of.path)
                        if any(fpath.startswith(a) for a in allowed):
                            continue
                        if any(fpath.startswith(s) for s in _RT_SENSITIVE_PREFIXES):
                            _sec_event(
                                "RUNTIME_FILE_ESCAPE",
                                f"pid={pid} opened restricted path={fpath!r}",
                                filename=bid,
                            )
                            _rt_kill_bot(
                                bid, pid,
                                f"opened restricted host path: {fpath!r}",
                            )
                            return   # Watchdog exits after kill
                        _sec_event(
                            "RUNTIME_FILE_SUSPICIOUS",
                            f"pid={pid} unexpected open file={fpath!r}",
                            filename=bid,
                        )
                except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                    break   # Process gone or unreadable
                except Exception as e:
                    _sec_event("WATCHDOG_PSUTIL_ERROR", str(e), filename=bid)

            else:
                try:
                    maps_path = f"/proc/{pid}/maps"
                    with open(maps_path, "r", errors="ignore") as mf:
                        for line in mf:
                            parts = line.split()
                            if len(parts) >= 6 and parts[5].startswith("/"):
                                fpath = os.path.realpath(parts[5])
                                if any(fpath.startswith(a) for a in allowed):
                                    continue
                                if any(fpath.startswith(s) for s in _RT_SENSITIVE_PREFIXES):
                                    _sec_event(
                                        "RUNTIME_MAPS_ESCAPE",
                                        f"pid={pid} mmap={fpath!r}",
                                        filename=bid,
                                    )
                except (PermissionError, FileNotFoundError, OSError):
                    pass
                except Exception as e:
                    _sec_event("WATCHDOG_MAPS_ERROR", str(e), filename=bid)

        except Exception as e:
            _sec_event("WATCHDOG_LOOP_ERROR", str(e), filename=bid)

    stop_evt.set()   # Mark as done regardless of exit path


def _start_watchdog(bid: str, pid: int, bot_dir: str, own_hosted_dir: Optional[str] = None) -> None:
    _stop_watchdog(bid)   # Stop any stale watchdog for this bid first
    evt = threading.Event()
    _watchdog_stop[bid] = evt
    t = threading.Thread(
        target=_watchdog_thread,
        args=(bid, pid, bot_dir, evt, own_hosted_dir),
        daemon=True,
        name=f"watchdog-{bid[:8]}",
    )
    t.start()
    _sec_event(
        "WATCHDOG_STARTED",
        f"pid={pid} bot_dir={bot_dir!r} own_hosted_dir={own_hosted_dir!r}",
        filename=bid,
    )


def _stop_watchdog(bid: str) -> None:
    evt = _watchdog_stop.pop(bid, None)
    if evt:
        evt.set()


def _auto_restart_bot(bid: str) -> None:
    """
    Called from the watchdog thread when a bot process dies naturally
    (not killed by the security watchdog).  Restarts the bot automatically
    with NO hard limit — bots run forever until manually stopped.

    Backoff schedule (exponential, capped at _RT_MAX_BACKOFF_SECS):
        attempt 1 →  10 s
        attempt 2 →  20 s
        attempt 3 →  40 s
        attempt 4 →  80 s
        attempt 5 → 160 s
        attempt 6+ → 300 s  (cap)

    The consecutive-crash counter resets after _RT_RESTART_WINDOW seconds of
    stable running, so a bot that recovers and runs fine for >5 min will get
    the base 10-second delay on the next crash.

    Restarts stop only when:
      • The user manually stops the bot (proc_stop sets status "manually_stopped")
      • The host bot process itself goes offline
    """
    now  = time.time()
    info = _restart_counts.get(bid, {"count": 0, "first_ts": now})

    # the bot has been stable; reset backoff to give it a clean slate.
    if now - info.get("first_ts", now) > _RT_RESTART_WINDOW:
        info = {"count": 0, "first_ts": now}

    try:
        b = get_bot(bid)
        if b and b.get("status") == "manually_stopped":
            _restart_counts.pop(bid, None)
            return
    except Exception:
        pass

    info["count"] += 1
    if info["count"] == 1:
        info["first_ts"] = now       # anchor the window on the first crash
    _restart_counts[bid] = info
    attempt = info["count"]

    delay = min(_RT_RESTART_COOLDOWN * (2 ** (attempt - 1)), _RT_MAX_BACKOFF_SECS)

    _sec_event(
        "AUTORESTART_SCHEDULED",
        f"attempt={attempt} backoff={delay}s",
        filename=bid,
    )
    try:
        with open(_log_path(bid), "a", encoding="utf-8") as lf:
            lf.write(
                f"[{_now_ist():%Y-%m-%d %H:%M:%S} IST] "
                f"── [AUTO-RESTART] 🔄 Attempt {attempt} —"
                f" restarting in {delay}s… ──\n"
            )
    except Exception:
        pass

    time.sleep(delay)

    try:
        b = get_bot(bid)
        if b and b.get("status") == "manually_stopped":
            _restart_counts.pop(bid, None)
            return
    except Exception:
        pass

    ok, msg = proc_start(bid)
    clean = re.sub(r"<[^<]+?>", "", msg)[:160]

    if ok:
        _sec_event("AUTORESTART_SUCCESS", f"attempt={attempt}", filename=bid)
        try:
            with open(_log_path(bid), "a", encoding="utf-8") as lf:
                lf.write(
                    f"[{_now_ist():%Y-%m-%d %H:%M:%S} IST] "
                    f"── [AUTO-RESTART] ✅ Bot restarted successfully"
                    f" (attempt {attempt}, backoff was {delay}s) ──\n"
                )
        except Exception:
            pass
    else:
        _sec_event(
            "AUTORESTART_FAILED",
            f"attempt={attempt} reason={clean!r}",
            filename=bid,
        )
        try:
            with open(_log_path(bid), "a", encoding="utf-8") as lf:
                lf.write(
                    f"[{_now_ist():%Y-%m-%d %H:%M:%S} IST] "
                    f"── [AUTO-RESTART] ❌ Attempt {attempt} failed: {clean}"
                    f" — will retry automatically… ──\n"
                )
        except Exception:
            pass
        # so schedule the next attempt directly from here.
        threading.Thread(
            target=_auto_restart_bot,
            args=(bid,),
            daemon=True,
            name=f"autorestart-{bid[:8]}",
        ).start()


MODULE_PACKAGE_MAP = {
      "PIL":           "Pillow",
      "cv2":           "opencv-python",
      "telegram":      "python-telegram-bot",
      "pyrogram":      "pyrogram",
      "telethon":      "telethon",
      "aiogram":       "aiogram",
      "pytgcalls":     "__NO_DEPS__pytgcalls",
      "tgcalls":       "__SKIP__",
      "Crypto":        "pycryptodome",
      "cryptography":  "cryptography",
      "tgcrypto":      "tgcrypto",
      "dotenv":        "python-dotenv",
      "yaml":          "PyYAML",
      "bs4":           "beautifulsoup4",
      "sklearn":       "scikit-learn",
      "aiohttp":       "aiohttp",
      "httpx":         "httpx",
      "requests":      "requests",
      "flask":         "flask",
      "fastapi":       "fastapi",
      "uvicorn":       "uvicorn",
      "starlette":     "starlette",
      "motor":         "motor",
      "pymongo":       "pymongo",
      "redis":         "redis",
      "psutil":        "psutil",
      "qrcode":        "qrcode[pil]",
      "barcode":       "python-barcode",
      "pydantic":      "pydantic",
      "apscheduler":   "APScheduler",
      "cachetools":    "cachetools",
      "dateutil":      "python-dateutil",
  }

  # has no PyPI wheel).

TOKEN_REGEX = re.compile(r"\b(\d{6,12}:[A-Za-z0-9_-]{30,})\b")

def extract_bot_token(filepath: str) -> Optional[str]:
    try:
        if not filepath or not os.path.exists(filepath):
            return None
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(200_000)
        m = TOKEN_REGEX.search(content)
        return m.group(1) if m else None
    except Exception:
        return None

def scan_file_for_token(filepath: str) -> Tuple[bool, str]:
    if not filepath or not os.path.exists(filepath):
        return False, "❌ <b>Error In Your File</b> — File not found on server.\n<b>Check logs for details.</b>"
    ext = file_ext(filepath)
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"❌ <b>Error In Your File</b> — Unsupported type <code>{h(ext)}</code>.\n<b>Check logs for details.</b>"
    if ext == ".py":
        token = extract_bot_token(filepath)
        return True, token or ""
    return True, ""

def _alive(pid: int) -> bool:
    """True only if pid exists AND is not a zombie. os.kill(pid, 0) alone
    returns True for zombies (exited but not yet reaped by the parent),
    which used to leave crashed bots stuck showing status=running with
    RAM reading 0.0 MB (a zombie's memory has already been freed)."""
    try:
        os.kill(pid, 0)
    except Exception:
        return False
    if _PSUTIL:
        try:
            if _psutil.Process(pid).status() == _psutil.STATUS_ZOMBIE:
                return False
        except Exception:
            return False
    return True

def _log_path(bid: str) -> str:
    return os.path.join(LOGS_DIR, f"{bid}.log")

def get_bot_logs(bid: str, lines: int = LOG_LINES) -> str:
    lp = _log_path(bid)
    b = get_bot(bid)
    bot_name = b.get("file_name", "unknown") if b else "unknown"
    uid = str(b.get("user_id", "")) if b else ""
    header = f"📋 <b>Logs for</b> <code>{h(bot_name)}</code>  <b>(User <code>{h(uid)}</code>)</b>:\n"

    if not os.path.exists(lp):
        body = "(No logs yet — start the bot to see output)"
    else:
        try:
            with open(lp, "r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
            tail = all_lines[-lines:] if len(all_lines) > lines else all_lines
            body = "".join(tail).strip() or "(Log file is empty)"
        except Exception as e:
            body = f"(Could not read logs: {e})"

    body_safe = h(body)
    if len(body_safe) > 3500:
        body_safe = "…(truncated)\n" + body_safe[-3500:]
    return header + f"<pre>{body_safe}</pre>"

def extract_missing_module(logs_text: str) -> Optional[str]:
    patterns = [
        r"ModuleNotFoundError:\s+No module named ['\"]([^'\"]+)['\"]",
        r"ImportError:\s+No module named ['\"]([^'\"]+)['\"]",
        r"ImportError:\s+cannot import name ['\"]?([^'\"\s]+)",
    ]
    for pattern in patterns:
        m = re.search(pattern, logs_text)
        if m:
            module = m.group(1).strip().split(".")[0]
            if module:
                return module
    return None

def package_for_module(module: str) -> str:
    return MODULE_PACKAGE_MAP.get(module, module)

def ensure_pip_available() -> Tuple[bool, str]:
    try:
        r = subprocess.run([sys.executable,"-m","pip","--version"],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
        if r.returncode == 0:
            return True, "pip available"
        e = subprocess.run([sys.executable,"-m","ensurepip","--upgrade"],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120)
        if e.returncode == 0:
            return True, "pip installed"
        return False, (e.stdout or "ensurepip failed").strip()
    except Exception as e:
        return False, str(e)

def _pip_install_pkg(pkg_specs: list, no_deps: bool = False, timeout: int = PIP_INSTALL_TIMEOUT) -> tuple:
    """
    Low-level pip install helper.
    pkg_specs: list of package specifiers, e.g. ["requests", "flask>=2.0"].
    Returns (returncode, combined_output_str).
    Automatically retries with --no-deps when a ResolutionImpossible /
    conflict error is detected and no_deps is not already set.
    Serialised with _pip_install_lock so parallel bot starts never write
    to PIP_TARGET_DIR at the same time (which corrupts installed packages).
    """
    with _pip_install_lock:
        cmd = [
            sys.executable, "-m", "pip", "install",
            "--target", PIP_TARGET_DIR,
            "--prefer-binary",
        ]
        if no_deps:
            cmd.append("--no-deps")
        cmd.extend(pkg_specs)
        try:
            r = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=timeout,
            )
            out = (r.stdout or "").strip()
            conflict_hints = (
                "resolutionimpossible", "conflicting dependencies",
                "no matching distribution", "could not find a version",
                "no version found", "dependency conflict",
            )
            if r.returncode != 0 and not no_deps and any(h in out.lower() for h in conflict_hints):
                cmd2 = [x for x in cmd if x != "--no-deps"] + ["--no-deps"]
                r2 = subprocess.run(
                    cmd2, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, timeout=timeout,
                )
                out2 = (r2.stdout or "").strip()
                if r2.returncode == 0:
                    return 0, out2 + "\n[note: installed with --no-deps due to dependency conflict]"
                return r2.returncode, out2
            return r.returncode, out
        except subprocess.TimeoutExpired:
            return -1, "pip install timed out"
        except Exception as ex:
            return -1, str(ex)


def auto_install_missing_module(module: str, bid: str) -> Tuple[bool, str]:
    raw_pkg = package_for_module(module)

    if raw_pkg == "__SKIP__":
        lp = _log_path(bid)
        try:
            with open(lp, "a", encoding="utf-8") as lf:
                lf.write(
                    f"[{_now_ist():%Y-%m-%d %H:%M:%S} IST] ── Skipping '{module}'"
                    " (no installable PyPI wheel) ──\n"
                )
        except Exception:
            pass
        return True, f"Skipped {module} (no installable wheel)"

    no_deps = False
    if raw_pkg.startswith("__NO_DEPS__"):
        no_deps = True
        package = raw_pkg[len("__NO_DEPS__"):]
    else:
        package = raw_pkg

    pkg_base = package.split("[")[0]  # strip extras like [pil]
    if not re.match(r"^[A-Za-z0-9_.-]+$", pkg_base):
        return False, f"Unsafe package name: {package}"

    lp = _log_path(bid)
    try:
        pip_ok, pip_msg = ensure_pip_available()
        if not pip_ok:
            with open(lp, "a", encoding="utf-8") as lf:
                lf.write(f"pip setup failed: {pip_msg}\n")
            return False, pip_msg

        with open(lp, "a", encoding="utf-8") as lf:
            lf.write(
                f"[{_now_ist():%Y-%m-%d %H:%M:%S} IST] ── Auto-installing '{package}'"
                " into pip_packages/ ──\n"
            )
            lf.flush()

        rc, out = _pip_install_pkg([package], no_deps=no_deps)

        with open(lp, "a", encoding="utf-8") as lf:
            lf.write(out + "\n")
            if rc == 0:
                lf.write(
                    f"[{_now_ist():%Y-%m-%d %H:%M:%S} IST] ── '{package}'"
                    " installed successfully ──\n"
                )

        if rc == 0:
            return True, f"Installed {package}"
        return False, out or f"pip install failed for {package}"
    except Exception as e:
        return False, str(e)


def _pre_install_basic_packages() -> None:
    BASIC_PKGS = [
        "python-telegram-bot>=20.0",
        "flask",
        "psutil",
        "requests",
        "cryptography",
        "aiohttp",
        "python-dotenv",
        "PyYAML",
        "httpx",
        "tgcrypto",
    ]
    pip_ok, _ = ensure_pip_available()
    if not pip_ok:
        return
    os.makedirs(PIP_TARGET_DIR, exist_ok=True)
    for pkg in BASIC_PKGS:
        try:
            _pip_install_pkg([pkg])
        except Exception:
            pass


def _file_content_hash(filepath: str) -> str:
    """SHA-256 of a file's bytes — used to detect whether a bot's code has
    changed since we last fully verified its imports."""
    try:
        h_ = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h_.update(chunk)
        return h_.hexdigest()
    except Exception:
        return ""


def invalidate_import_verification(bid: Optional[str] = None) -> None:
    """
    Forces a fresh import scan on the next start for one bot (or, if bid is
    None, for every bot). Call this whenever the shared package environment
    changes — e.g. after a manual pip uninstall — so a bot that was
    previously verified but now relies on a removed package gets re-checked
    instead of skipping straight to launch.
    """
    d = _load()
    targets = [bid] if bid else list(d["bots"].keys())
    changed = False
    for _bid in targets:
        b = d["bots"].get(_bid)
        if b and b.get("verified_import_hash"):
            b.pop("verified_import_hash", None)
            changed = True
    if changed:
        _save(d)


def scan_and_install_all_imports(filepath: str, bid: str) -> Tuple[int, int, list]:
    """
    Parse every import statement in a .py file and pre-install any missing
    packages before the bot is launched.

    Skips the whole scan when this exact file content was already fully
    verified (every import resolves) on a previous start/restart — so
    restarting a bot never re-checks or re-installs modules that are
    already known to be present. Only a change to the file's content
    (e.g. replacing it) triggers a fresh scan.

    Returns (installed_count, failed_count, failed_list).
    """
    if not filepath or not os.path.exists(filepath):
        return 0, 0, []
    ext = file_ext(filepath)

    if ext != ".py":
        return 0, 0, []

    file_hash = _file_content_hash(filepath)
    if file_hash:
        b = get_bot(bid)
        if b and b.get("verified_import_hash") == file_hash:
            return 0, 0, []  # unchanged & already fully verified — nothing to do

    import_pat = re.compile(
        r"^\s*(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)",
        re.MULTILINE,
    )
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read(500_000)
    except Exception:
        return 0, 0, []

    modules_found = set(m.group(1) for m in import_pat.finditer(source))

    stdlib_mods = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else set()
    always_skip = {
        "os", "sys", "re", "json", "time", "datetime", "math", "random",
        "string", "io", "pathlib", "shutil", "subprocess", "threading",
        "asyncio", "logging", "traceback", "functools", "itertools",
        "collections", "contextlib", "copy", "struct", "hashlib", "hmac",
        "base64", "binascii", "uuid", "socket", "ssl", "http", "urllib",
        "email", "html", "xml", "csv", "sqlite3", "typing", "abc",
        "dataclasses", "enum", "warnings", "inspect", "types", "weakref",
        "gc", "signal", "resource", "grp", "pwd", "stat", "tempfile",
        "glob", "fnmatch", "pickle", "shelve", "gzip", "zipfile", "tarfile",
        "configparser", "argparse", "getpass", "platform", "locale",
        "textwrap", "__future__", "builtins",
    }
    to_check = modules_found - stdlib_mods - always_skip

    if not to_check:
        return 0, 0, []

    lp = _log_path(bid)
    installed = 0
    failed = 0
    failed_list = []

    with open(lp, "a", encoding="utf-8") as lf:
        lf.write(
            f"[{_now_ist():%Y-%m-%d %H:%M:%S} IST] ── Pre-start: scanning {len(to_check)} import(s) ──\n"
        )

    for module in sorted(to_check):
        check_env = {
            k: v for k, v in os.environ.items()
            if k in {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "LD_LIBRARY_PATH"}
        }
        check_env["PYTHONPATH"] = PIP_TARGET_DIR + os.pathsep + os.environ.get("PYTHONPATH", "")
        try:
            r = subprocess.run(
                [sys.executable, "-c", f"import {module}"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=10, env=check_env,
            )
            if r.returncode == 0:
                continue  # already importable — skip
        except Exception:
            pass

        ok, msg = auto_install_missing_module(module, bid)
        if ok:
            installed += 1
        else:
            failed += 1
            failed_list.append(module)

    with open(lp, "a", encoding="utf-8") as lf:
        lf.write(
            f"[{_now_ist():%Y-%m-%d %H:%M:%S} IST] ── Pre-start scan done: "
            f"{installed} installed, {failed} failed ──\n"
        )

    # Only remember this file as "fully verified" if every import resolved.
    # If something failed, we deliberately do NOT cache the hash, so the
    # next start attempt will retry installing the missing package(s).
    if failed == 0 and file_hash:
        upd_bot(bid, {"verified_import_hash": file_hash})

    return installed, failed, failed_list

def _launch_process(bid: str, b: dict, fp: str) -> Tuple[bool, str, Optional[int], Optional[int]]:
    lp = _log_path(bid)
    log_file = open(lp, "a", encoding="utf-8")
    log_file.write(f"\n[{_now_ist():%Y-%m-%d %H:%M:%S} IST] ── Bot started ──\n")
    log_file.flush()
    cmd, cmd_error = start_command_for_file(fp)
    if cmd_error:
        log_file.write(cmd_error + "\n")
        log_file.flush()
        log_file.close()
        return False, cmd_error, None, None

    # etc.) stay separate from the uploaded bot script in HOSTED_FILES_DIR.
    _uid_s  = str(b.get("user_id", "unknown"))
    bot_dir = os.path.join(BOT_DATA_DIR, _uid_s, bid)
    os.makedirs(bot_dir, exist_ok=True)

    # file inside the namespace — the rest of HOSTED_FILES_DIR stays hidden.
    sandboxed_cmd = _build_sandbox_cmd(cmd, bot_dir, script_path=fp)

    # which lives in HOSTED_FILES_DIR (separate from bot_dir).
    child_env = _build_clean_env(bot_dir, script_path=fp)

    try:
        p = subprocess.Popen(
            sandboxed_cmd,
            stdout=log_file,
            stderr=log_file,
            cwd=bot_dir,
            preexec_fn=lambda: _sandbox_preexec(bot_dir),
            env=child_env,
        )
    except Exception:
        log_file.close()
        raise
    for _ in range(150):  # 15s window (was 5s) — python-telegram-bot needs longer to init
        if p.poll() is not None:
            break
        time.sleep(0.1)
    if p.poll() is not None:
        log_file.flush()
        ec = p.returncode
        log_file.write(f"[{_now_ist():%Y-%m-%d %H:%M:%S} IST] ── Bot exited early ({ec}) ──\n")
        log_file.close()
        logs_text = get_bot_logs(bid, 12)
        return False, logs_text, ec, None
    _procs[bid] = (p, log_file)
    b2 = get_bot(bid)
    ipid = b2.get("internal_pid", "?") if b2 else "?"
    upd_bot(bid, {"status": "running", "pid": p.pid, "started_at": _now()})
    # This bot's own upload folder (HOSTED_FILES_DIR/<uid>/<bid>) ONLY —
    # not the shared HOSTED_FILES_DIR root and not any other bot's folder.
    # Some uploaded scripts resolve relative paths like "data/bot.db"
    # against the folder they were uploaded to rather than the bot_dir cwd,
    # so the watchdog needs to allow exactly that one folder too.
    own_hosted_dir = os.path.join(HOSTED_FILES_DIR, _uid_s, bid)
    _start_watchdog(bid, p.pid, bot_dir, own_hosted_dir)
    return True, f"✅ <b>Bot started!</b>\n🔢 <b>Bot #</b><code>{ipid}</code>\n🖥️ <b>OS PID:</b> <code>{p.pid}</code>", None, p.pid

def proc_start(bid: str) -> Tuple[bool, str]:
    b = get_bot(bid)
    if not b:
        return False, "❌ <b>Bot not found.</b>"
    if b.get("pending"):
        return False, "⏳ <b>This bot is awaiting owner approval.</b>"

    fp = get_runnable_file_path(bid, b)
    if not fp:
        upd_bot(bid, {"status": "stopped", "pid": None})
        return False, "❌ <b>File missing from server.</b>"

    has_token, scan_msg = scan_file_for_token(fp)
    if not has_token:
        upd_bot(bid, {"status": "error", "pid": None})
        lp = _log_path(bid)
        with open(lp, "a", encoding="utf-8") as lf:
            lf.write(f"[{_now_ist():%Y-%m-%d %H:%M:%S} IST] ── Pre-start scan failed: {scan_msg} ──\n")
        return False, scan_msg

    if scan_msg and ":" in scan_msg:
        upd_bot(bid, {"bot_token": _encrypt_token(scan_msg)})
        add_hosted_bot_users_bulk(scan_msg, [])

    token_to_check = scan_msg if (scan_msg and ":" in scan_msg) else get_decrypted_bot_token(b)
    if token_to_check:
        for other_bid, other_b in all_bots().items():
            if other_bid == bid:
                continue
            other_tok = get_decrypted_bot_token(other_b) or extract_bot_token(other_b.get("file_path",""))
            if other_tok == token_to_check and other_b.get("status") == "running" and other_b.get("pid") and _alive(other_b["pid"]):
                return False, (
                    f"⚠️ <b>1 bot is already running with this token in file.</b>\n\n"
                    f"📄 <code>{h(other_b.get('file_name',''))}</code> is already running with the same bot token.\n"
                    f"<b>Stop the existing bot before starting this one.</b>"
                )

    if b.get("status") == "running" and b.get("pid") and _alive(b["pid"]):
        return False, "⚠️ <b>Bot is already running.</b>"

    # ── Pre-execution integrity check (symlink / hardlink / path containment)
    _uid_for_check = b.get("user_id")
    ok_pre, reason_pre = _pre_exec_file_check(fp, bid, user_id=_uid_for_check)
    if not ok_pre:
        upd_bot(bid, {"status": "error", "pid": None, "security_blocked": True, "security_block_reason": reason_pre})
        lp = _log_path(bid)
        with open(lp, "a", encoding="utf-8") as lf:
            lf.write(
                f"[{_now_ist():%Y-%m-%d %H:%M:%S} IST] "
                f"── Pre-exec check blocked: {reason_pre} ──\n"
            )
        return False, reason_pre

    try:
        ext = file_ext(fp)
        scan_and_install_all_imports(fp, bid)

        ok, launch_msg, exit_code, _pid = _launch_process(bid, b, fp)
        if ok:
            threading.Thread(
                target=set_branding_bio_for_free_bot,
                args=(bid,),
                daemon=True,
            ).start()
            return True, launch_msg
        missing_module = extract_missing_module(launch_msg)
        if missing_module and ext == ".py":
            install_ok, install_msg = auto_install_missing_module(missing_module, bid)
            if install_ok:
                ok2, retry_msg, retry_exit, _retry_pid = _launch_process(bid, b, fp)
                if ok2:
                    threading.Thread(
                        target=set_branding_bio_for_free_bot,
                        args=(bid,),
                        daemon=True,
                    ).start()
                    return True, (
                        f"✅ <b>Missing module auto-installed &amp; bot started!</b>\n"
                        f"📦 <b>Package:</b> <code>{h(package_for_module(missing_module))}</code>\n\n{retry_msg}"
                    )
                upd_bot(bid, {"status": "error", "pid": None})
                return False, f"🟡 <b>Error In Your File</b>\n<b>Check logs for details.</b>\n\nExit: <code>{retry_exit}</code>"
            upd_bot(bid, {"status": "error", "pid": None})
            return False, f"🟡 <b>Error In Your File</b>\n<b>Check logs for details.</b>\n\nModule: <code>{h(missing_module)}</code>"
        upd_bot(bid, {"status": "error", "pid": None})
        return False, f"🟡 <b>Error In Your File</b>\n<b>Check logs for details.</b>\n\nExit: <code>{exit_code}</code>"
    except Exception as e:
        upd_bot(bid, {"status": "error", "pid": None})
        return False, f"🟡 <b>Error In Your File</b>\n<b>Check logs for details.</b>\n\n<code>{h(e)}</code>"


def proc_force_start(bid: str) -> Tuple[bool, str]:
    """
    Admin-power force-start: bypasses ALL security and token scans.
    Clears the security_blocked flag and launches the bot directly.
    Only callable by admins — never expose to regular users.
    """
    b = get_bot(bid)
    if not b:
        return False, "❌ <b>Bot not found.</b>"

    fp = get_runnable_file_path(bid, b)
    if not fp:
        upd_bot(bid, {"status": "stopped", "pid": None})
        return False, "❌ <b>File missing from server.</b>"

    if b.get("status") == "running" and b.get("pid") and _alive(b["pid"]):
        return False, "⚠️ <b>Bot is already running.</b>"

    upd_bot(bid, {"security_blocked": False, "security_block_reason": ""})

    try:
        ext = file_ext(fp)
        scan_and_install_all_imports(fp, bid)

        ok, msg, _ec, _pid = _launch_process(bid, b, fp)

        if not ok:
            upd_bot(bid, {"status": "error", "pid": None})
        return ok, msg
    except Exception as e:
        upd_bot(bid, {"status": "error", "pid": None})
        return False, f"🟡 <b>Force-start error:</b> <code>{h(str(e))}</code>"


def proc_stop(bid: str) -> Tuple[bool, str]:
    b = get_bot(bid)
    if not b:
        return False, "❌ <b>Bot not found.</b>"
    entry = _procs.pop(bid, None)

    # entry is (process, log_file) for a running .py bot.
    # (Older installs may still have a list-of-procs entry from a legacy
    # ZIP bot — handled generically below for a clean shutdown.)
    if isinstance(entry, tuple):
        proc_or_list, lf = entry
        procs_to_kill = proc_or_list if isinstance(proc_or_list, list) else [proc_or_list]
    else:
        procs_to_kill = []
        lf = None

    for p in procs_to_kill:
        if p is None:
            continue
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass

    if lf:
        try:
            lf.write(f"[{_now_ist():%Y-%m-%d %H:%M:%S} IST] ── Bot stopped ──\n")
            lf.close()
        except Exception:
            pass
    elif not procs_to_kill and b.get("pid"):
        try:
            os.kill(b["pid"], signal.SIGTERM)
        except Exception:
            try:
                os.kill(b["pid"], signal.SIGKILL)
            except Exception:
                pass

    upd_bot(bid, {"status": "manually_stopped", "pid": None, "started_at": None, "stopped_at": _now()})
    # Stop the runtime watchdog thread for this bot
    _stop_watchdog(bid)
    # Reset auto-restart counter — explicit stop gives a clean slate
    _restart_counts.pop(bid, None)
    # Clean up any temp-decrypted file that was used to run this bot
    cleanup_temp_decrypt(bid)
    return True, "✅ <b>Bot stopped successfully.</b>"

def proc_restart(bid: str) -> Tuple[bool, str]:
    proc_stop(bid)
    return proc_start(bid)

#  START-ALL CANCELLATION — a module-level flag so the admin can abort an
#  in-progress "Start All" sweep from the Telegram UI. Checked between every
#  bot launch (and in small slices during the inter-bot delay) so a cancel
#  request lands within ~0.1s instead of waiting out the full sweep.
_start_all_cancel = threading.Event()
_start_all_active = False

def proc_start_all() -> dict:
    sync_statuses()
    result = {"started":0,"already":0,"skipped":0,"failed":0,"cancelled":0,
               "was_cancelled": False, "errors":[],"usernames":[]}
    started_bids = []
    for bid, b in all_bots().items():
        if _start_all_cancel.is_set():
            result["was_cancelled"] = True
            result["cancelled"] += 1
            continue
        if b.get("pending"):
            result["skipped"] += 1
            continue
        if b.get("status") == "running" and b.get("pid") and _alive(b["pid"]):
            result["already"] += 1
            continue
        # One-by-one: each bot's start attempt fully completes (success or
        # failure) before the loop moves on to the next bot.
        ok, msg = proc_start(bid)
        if ok:
            result["started"] += 1
            started_bids.append(bid)
        else:
            result["failed"] += 1
            result["errors"].append(f"{b.get('file_name',bid)}: {re.sub('<[^<]+?>','',msg)[:160]}")
        # delay between each bot start to prevent crashes, sliced so a
        # cancel request doesn't have to wait out the full second
        for _ in range(10):
            if _start_all_cancel.is_set():
                result["was_cancelled"] = True
                break
            time.sleep(0.1)
        if _start_all_cancel.is_set():
            continue
    # Re-sync after launching all bots: some may have crashed in the seconds
    # between their startup check passing and this point.  Without this, bots
    # that exited immediately after the liveness window show as "running".
    time.sleep(2)
    sync_statuses()
    # Recount to reflect true post-launch state
    result["started"] = sum(
        1 for b in all_bots().values()
        if b.get("status") == "running" and b.get("pid") and _alive(b["pid"])
           and not b.get("pending")
    ) - result["already"]
    result["started"] = max(0, result["started"])

    # Resolve each newly-started bot's @username from its own token via
    # Telegram's getMe, so the admin gets a readable list, not just a count.
    for bid in started_bids:
        fresh = get_bot(bid)
        if not fresh:
            continue
        if not (fresh.get("status") == "running" and fresh.get("pid") and _alive(fresh["pid"])):
            continue
        tok = get_decrypted_bot_token(fresh) or extract_bot_token(fresh.get("file_path", ""))
        uname = ""
        if tok:
            try:
                info = hosted_bot_get_me(tok)
                uname = (info or {}).get("username", "") or ""
            except Exception:
                uname = ""
        result["usernames"].append(f"@{uname}" if uname else fresh.get("file_name", bid))

    return result

def proc_stop_all() -> dict:
    sync_statuses()
    result = {"stopped":0,"already":0,"failed":0,"errors":[]}
    for bid, b in all_bots().items():
        if b.get("status") != "running" and not b.get("pid"):
            result["already"] += 1
            continue
        ok, msg = proc_stop(bid)
        if ok:
            result["stopped"] += 1
        else:
            result["failed"] += 1
            result["errors"].append(f"{b.get('file_name',bid)}: {re.sub('<[^<]+?>','',msg)[:160]}")
    return result

def sync_statuses():
    for bid, b in all_bots().items():
        pid = b.get("pid")
        if b.get("status") == "running" and pid:
            # Reap first: .poll() calls waitpid(WNOHANG) under the hood,
            # which clears a zombie entry the instant it's found so it
            # doesn't sit around lying about being "alive".
            entry_peek = _procs.get(bid)
            if isinstance(entry_peek, tuple):
                proc_or_list, _ = entry_peek
                for p in (proc_or_list if isinstance(proc_or_list, list) else [proc_or_list]):
                    if p is not None:
                        try:
                            p.poll()
                        except Exception:
                            pass
        if b.get("status") == "running" and pid and not _alive(pid):
            entry = _procs.pop(bid, None)
            if isinstance(entry, tuple):
                proc_or_list, log_file = entry
                procs = proc_or_list if isinstance(proc_or_list, list) else [proc_or_list]
            else:
                procs = []
                log_file = None

            # For ZIP bots: if ANY process is still alive, don't mark as stopped
            if any(p is not None and _alive(p.pid) for p in procs):
                _procs[bid] = entry
                continue

            ec = None
            for p in procs:
                if p is not None:
                    try:
                        ec = p.poll()
                    except Exception:
                        pass
            new_status = "error" if (ec is not None and ec != 0) else "stopped"
            upd_bot(bid, {"status": new_status, "pid": None, "started_at": None, "stopped_at": _now()})
            if log_file:
                try:
                    log_file.close()
                except Exception:
                    pass


def detect_hosting_platform() -> str:
    """Best-effort detection of which platform this instance is running on,
    based on environment variables/markers common hosts set."""
    env = os.environ
    if env.get("REPL_ID") or env.get("REPLIT_DB_URL") or env.get("REPL_SLUG"):
        return "Replit"
    if env.get("RENDER") or env.get("RENDER_SERVICE_NAME"):
        return "Render"
    if env.get("RAILWAY_ENVIRONMENT") or env.get("RAILWAY_PROJECT_NAME"):
        return "Railway"
    if env.get("DYNO"):
        return "Heroku"
    if env.get("FLY_APP_NAME"):
        return "Fly.io"
    if env.get("KOYEB_APP_NAME") or env.get("KOYEB_SERVICE_ID"):
        return "Koyeb"
    if env.get("VERCEL"):
        return "Vercel"
    if env.get("K_SERVICE") or env.get("K_REVISION"):
        return "Google Cloud Run"
    if env.get("AWS_EXECUTION_ENV") or env.get("AWS_LAMBDA_FUNCTION_NAME"):
        return "AWS"
    if env.get("AZURE_FUNCTIONS_ENVIRONMENT") or env.get("WEBSITE_INSTANCE_ID"):
        return "Azure"
    if env.get("PYTHONANYWHERE_DOMAIN") or env.get("PYTHONANYWHERE_SITE"):
        return "PythonAnywhere"
    if env.get("TERMUX_VERSION") or "com.termux" in env.get("PREFIX", ""):
        return "Termux (Android)"
    if os.path.exists("/.dockerenv"):
        return "Docker Container"
    try:
        host = socket.gethostname() or "VPS"
    except Exception:
        host = "VPS"
    return f"VPS / Server ({host})"


def _ram_from_proc_meminfo() -> Optional[dict]:
    """Fallback RAM reader for when psutil isn't installed (Linux only)."""
    try:
        vals = {}
        with open("/proc/meminfo") as f:
            for line in f:
                key, _, rest = line.partition(":")
                if key in ("MemTotal", "MemAvailable"):
                    vals[key] = int(rest.strip().split()[0])  # kB
        if "MemTotal" not in vals or "MemAvailable" not in vals:
            return None
        total_kb = vals["MemTotal"]
        avail_kb = vals["MemAvailable"]
        used_kb = max(total_kb - avail_kb, 0)
        pct = (used_kb / total_kb * 100) if total_kb else 0.0
        return {
            "ram_used": f"{used_kb/1024:.0f} MB",
            "ram_total": f"{total_kb/1024:.0f} MB",
            "ram_pct": f"{pct:.1f}%",
        }
    except Exception:
        return None


def get_system_stats() -> dict:
    info = {}
    info["platform"] = detect_hosting_platform()
    try:
        info["server_name"] = socket.gethostname() or "unknown"
    except Exception:
        info["server_name"] = "unknown"
    if _PSUTIL:
        try:
            # interval=None is non-blocking (returns usage since the last call
            # instead of sleeping for 0.5s to sample). A blocking sleep here
            # froze the whole event loop on every stats view.
            info["cpu"] = f"{_psutil.cpu_percent(interval=None):.1f}%"
            mem = _psutil.virtual_memory()
            info["ram_used"] = f"{mem.used/1024/1024:.0f} MB"
            info["ram_total"] = f"{mem.total/1024/1024:.0f} MB"
            info["ram_pct"] = f"{mem.percent:.1f}%"
        except Exception:
            pass
    # Fallback RAM reading (works even without psutil installed).
    if not info.get("ram_used"):
        ram_fallback = _ram_from_proc_meminfo()
        if ram_fallback:
            info.update(ram_fallback)
    # Disk usage via stdlib shutil — always available, no psutil needed.
    try:
        disk = shutil.disk_usage("/")
        info["disk_used"] = f"{disk.used/1024/1024/1024:.1f} GB"
        info["disk_total"] = f"{disk.total/1024/1024/1024:.1f} GB"
    except Exception:
        pass
    try:
        proc = _psutil.Process(os.getpid()) if _PSUTIL else None
        if proc:
            info["bot_ram"] = f"{proc.memory_info().rss/1024/1024:.1f} MB"
    except Exception:
        pass
    return info

_bot_psutil_procs: dict = {}   # pid -> primed psutil.Process, reused for non-blocking cpu_percent()

def get_bot_proc_info(bid: str) -> dict:
    info = {}
    b = get_bot(bid)
    if not b or not _PSUTIL:
        return info
    pid = b.get("pid")
    if not pid:
        return info
    try:
        proc = _bot_psutil_procs.get(pid)
        if proc is None or proc.pid != pid or not proc.is_running():
            proc = _psutil.Process(pid)
            proc.cpu_percent(interval=None)   # prime baseline — first read after this is 0.0
            if len(_bot_psutil_procs) > 500:  # cheap safety net against unbounded growth
                _bot_psutil_procs.clear()
            _bot_psutil_procs[pid] = proc
        # Non-blocking: reuses the same Process handle instead of sleeping
        # 0.3s per bot inside a handler (which froze the whole event loop).
        info["cpu"] = f"{proc.cpu_percent(interval=None):.1f}%"
        info["ram"] = f"{proc.memory_info().rss/1024/1024:.1f} MB"
        info["threads"] = str(proc.num_threads())
    except Exception as e:
        log.warning("get_bot_proc_info(%s) failed for pid=%s: %s", bid, pid, e)
    return info

def get_bot_ram_mb(bid: str):
    """Live RSS (MB, float) for a running hosted bot's process tree — includes
    child processes so ZIP bots with helper subprocesses are measured fully.
    Returns None if unavailable (psutil missing, bot not running, etc.)."""
    if not _PSUTIL:
        return None
    b = get_bot(bid)
    if not b:
        return None
    pid = b.get("pid")
    if not pid:
        return None
    try:
        proc = _psutil.Process(pid)
        total = proc.memory_info().rss
        for child in proc.children(recursive=True):
            try:
                total += child.memory_info().rss
            except Exception:
                pass
        return total / 1024 / 1024
    except Exception as e:
        log.warning("get_bot_ram_mb(%s) failed for pid=%s: %s", bid, pid, e)
        return None

#  TELEGRAM API HELPERS FOR HOSTED BOTS

def _tg_api(token: str, method: str, params: dict, timeout: int = 20) -> dict:
    url = f"https://api.telegram.org/bot{token}/{method}"
    try:
        data = _urlparse.urlencode(params, doseq=True).encode()
        req = _urlreq.Request(url, data=data, method="POST")
        with _urlreq.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="ignore")
        return json.loads(body)
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _tg_get(token: str, method: str, params: dict, timeout: int = 20) -> dict:
    url = f"https://api.telegram.org/bot{token}/{method}?" + _urlparse.urlencode(params)
    try:
        req = _urlreq.Request(url)
        with _urlreq.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="ignore")
        return json.loads(body)
    except Exception as e:
        return {"ok": False, "error": str(e)}

def hosted_bot_get_me(token: str) -> Optional[dict]:
    if not token:
        return None
    res = _tg_api(token, "getMe", {})
    return res.get("result") if res.get("ok") else None

async def auto_fetch_bot_username(token: str) -> str:
    """Ask Telegram (via getMe) for the real @username tied to a bot token.
    Runs the blocking HTTP call in a thread so we never block the event loop.
    Returns "" if the token is missing/invalid or the lookup fails."""
    if not token:
        return ""
    try:
        info = await asyncio.get_running_loop().run_in_executor(None, hosted_bot_get_me, token)
        return (info or {}).get("username", "") or ""
    except Exception:
        return ""

def hosted_bot_send_text(token: str, chat_id: int, text: str) -> Tuple[bool, Optional[int]]:
    res = _tg_api(token, "sendMessage", {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    })
    if res.get("ok"):
        return True, res["result"].get("message_id")
    return False, None

def hosted_bot_send_photo(token: str, chat_id: int, photo_url: str, caption: str = "") -> Tuple[bool, Optional[int]]:
    params = {"chat_id": chat_id, "photo": photo_url}
    if caption:
        params["caption"] = caption
        params["parse_mode"] = "HTML"
    res = _tg_api(token, "sendPhoto", params)
    if res.get("ok"):
        return True, res["result"].get("message_id")
    return False, None


def _entities_to_json(entities) -> list:
    if not entities:
        return []
    out = []
    for e in entities:
        d: dict = {
            "type":   e.type,
            "offset": e.offset,
            "length": e.length,
        }
        if e.url:
            d["url"] = e.url
        if e.language:
            d["language"] = e.language
        # custom_emoji_id is the key field for Premium emoji entities
        if getattr(e, "custom_emoji_id", None):
            d["custom_emoji_id"] = e.custom_emoji_id
        out.append(d)
    return out

def hosted_bot_send_text_rich(
    token: str, chat_id: int, text: str, entities=None
) -> Tuple[bool, Optional[int]]:
    """Send a text message preserving all entities including Premium emoji.

    When *entities* are provided they are passed as-is to the Bot API
    (no parse_mode) so custom_emoji entities survive the round-trip.
    Falls back to HTML parse_mode when no entities are supplied.
    """
    params: dict = {"chat_id": chat_id, "text": text, "disable_web_page_preview": "true"}
    ent_list = _entities_to_json(entities) if entities else []
    if ent_list:
        import json as _json
        params["entities"] = _json.dumps(ent_list)
    else:
        params["parse_mode"] = "HTML"
    res = _tg_api(token, "sendMessage", params)
    if res.get("ok"):
        return True, res["result"].get("message_id")
    return False, None

def hosted_bot_send_sticker(
    token: str, chat_id: int, file_id: str
) -> Tuple[bool, Optional[int]]:
    """Send a sticker (including animated / video stickers) via a hosted bot.

    Telegram file_ids are reusable across bots on the same server, so the
    file_id captured by the hosting bot can be forwarded through any other
    bot without re-downloading.
    """
    res = _tg_api(token, "sendSticker", {"chat_id": chat_id, "sticker": file_id})
    if res.get("ok"):
        return True, res["result"].get("message_id")
    return False, None

def hosted_bot_send_animation(
    token: str, chat_id: int, file_id: str,
    caption: str = "", caption_entities=None
) -> Tuple[bool, Optional[int]]:
    """Send a GIF / animation via a hosted bot, preserving caption entities."""
    params: dict = {"chat_id": chat_id, "animation": file_id}
    if caption:
        params["caption"] = caption
        ent_list = _entities_to_json(caption_entities) if caption_entities else []
        if ent_list:
            import json as _json
            params["caption_entities"] = _json.dumps(ent_list)
        else:
            params["parse_mode"] = "HTML"
    res = _tg_api(token, "sendAnimation", params)
    if res.get("ok"):
        return True, res["result"].get("message_id")
    return False, None

def hosted_bot_send_video_fid(
    token: str, chat_id: int, file_id: str,
    caption: str = "", caption_entities=None
) -> Tuple[bool, Optional[int]]:
    """Send a video via a hosted bot using an existing file_id."""
    params: dict = {"chat_id": chat_id, "video": file_id}
    if caption:
        params["caption"] = caption
        ent_list = _entities_to_json(caption_entities) if caption_entities else []
        if ent_list:
            import json as _json
            params["caption_entities"] = _json.dumps(ent_list)
        else:
            params["parse_mode"] = "HTML"
    res = _tg_api(token, "sendVideo", params)
    if res.get("ok"):
        return True, res["result"].get("message_id")
    return False, None

def hosted_bot_send_doc_fid(
    token: str, chat_id: int, file_id: str,
    caption: str = "", caption_entities=None
) -> Tuple[bool, Optional[int]]:
    """Send a document via a hosted bot using an existing file_id."""
    params: dict = {"chat_id": chat_id, "document": file_id}
    if caption:
        params["caption"] = caption
        ent_list = _entities_to_json(caption_entities) if caption_entities else []
        if ent_list:
            import json as _json
            params["caption_entities"] = _json.dumps(ent_list)
        else:
            params["parse_mode"] = "HTML"
    res = _tg_api(token, "sendDocument", params)
    if res.get("ok"):
        return True, res["result"].get("message_id")
    return False, None

def hosted_bot_send_voice_fid(
    token: str, chat_id: int, file_id: str,
    caption: str = "", caption_entities=None
) -> Tuple[bool, Optional[int]]:
    """Send a voice message via a hosted bot using an existing file_id."""
    params: dict = {"chat_id": chat_id, "voice": file_id}
    if caption:
        params["caption"] = caption
        ent_list = _entities_to_json(caption_entities) if caption_entities else []
        if ent_list:
            import json as _json
            params["caption_entities"] = _json.dumps(ent_list)
        else:
            params["parse_mode"] = "HTML"
    res = _tg_api(token, "sendVoice", params)
    if res.get("ok"):
        return True, res["result"].get("message_id")
    return False, None

def hosted_bot_send_audio_fid(
    token: str, chat_id: int, file_id: str,
    caption: str = "", caption_entities=None
) -> Tuple[bool, Optional[int]]:
    """Send an audio file via a hosted bot using an existing file_id."""
    params: dict = {"chat_id": chat_id, "audio": file_id}
    if caption:
        params["caption"] = caption
        ent_list = _entities_to_json(caption_entities) if caption_entities else []
        if ent_list:
            import json as _json
            params["caption_entities"] = _json.dumps(ent_list)
        else:
            params["parse_mode"] = "HTML"
    res = _tg_api(token, "sendAudio", params)
    if res.get("ok"):
        return True, res["result"].get("message_id")
    return False, None

def hosted_bot_send_photo_fid(
    token: str, chat_id: int, file_id: str,
    caption: str = "", caption_entities=None
) -> Tuple[bool, Optional[int]]:
    """Send a photo via a hosted bot using an existing file_id (not a URL).

    Preserves caption entities including Premium emoji.
    """
    params: dict = {"chat_id": chat_id, "photo": file_id}
    if caption:
        params["caption"] = caption
        ent_list = _entities_to_json(caption_entities) if caption_entities else []
        if ent_list:
            import json as _json
            params["caption_entities"] = _json.dumps(ent_list)
        else:
            params["parse_mode"] = "HTML"
    res = _tg_api(token, "sendPhoto", params)
    if res.get("ok"):
        return True, res["result"].get("message_id")
    return False, None

def hosted_bot_copy_msg(
    token: str, chat_id: int, msg
) -> Tuple[bool, Optional[int]]:
    """Copy any supported message type through a hosted bot to *chat_id*.

    Supported: text (with Premium emoji via entities), sticker (all kinds
    including animated/video), animation/GIF, photo, video, document,
    voice, audio.  Falls back to text+caption for unknown types.

    Uses file_id reuse: a file_id captured by the hosting bot is valid for
    any other bot on the same Telegram server, so no re-download is needed.
    """
    caption     = (msg.caption or "").strip()
    cap_ents    = msg.caption_entities or []

    if msg.sticker:
        return hosted_bot_send_sticker(token, chat_id, msg.sticker.file_id)

    if msg.animation:
        return hosted_bot_send_animation(
            token, chat_id, msg.animation.file_id, caption, cap_ents
        )

    if msg.photo:
        best = max(msg.photo, key=lambda p: p.file_size)
        return hosted_bot_send_photo_fid(
            token, chat_id, best.file_id, caption, cap_ents
        )

    if msg.video:
        return hosted_bot_send_video_fid(
            token, chat_id, msg.video.file_id, caption, cap_ents
        )

    if msg.voice:
        return hosted_bot_send_voice_fid(
            token, chat_id, msg.voice.file_id, caption, cap_ents
        )

    if msg.audio:
        return hosted_bot_send_audio_fid(
            token, chat_id, msg.audio.file_id, caption, cap_ents
        )

    if msg.document:
        return hosted_bot_send_doc_fid(
            token, chat_id, msg.document.file_id, caption, cap_ents
        )

    txt = (msg.text or "").strip()
    if txt:
        return hosted_bot_send_text_rich(token, chat_id, txt, msg.entities)

    # Nothing sendable found
    return False, None


def fetch_hosted_bot_users_from_updates(token: str) -> list:
    user_ids = set()
    try:
        res = _tg_get(token, "getUpdates", {"limit": 100, "offset": -100})
        if res.get("ok"):
            for upd in res.get("result", []):
                for source in ["message", "callback_query", "edited_message", "channel_post"]:
                    obj = upd.get(source)
                    if obj:
                        user = obj.get("from") or obj.get("message", {}).get("from")
                        if user and user.get("id"):
                            user_ids.add(int(user["id"]))
                            break
    except Exception:
        pass
    return list(user_ids)

def _bb_pickable_bots() -> list:
    result = []
    for bid, b in all_bots().items():
        tok = get_decrypted_bot_token(b) or extract_bot_token(b.get("file_path",""))
        if tok:
            info = hosted_bot_get_me(tok) or {}
            result.append({
                "bid": bid,
                "token": tok,
                "username": info.get("username",""),
                "name": info.get("first_name") or b.get("file_name","bot"),
            })
    return result

#  FREE-USER BIO ENFORCEMENT

HOSTING_BOT_BIO = "𝑷𝒐𝒘𝒆𝒓𝒆𝒅 𝒃𝒚 @UnknownXhosting_Bot 🪽"
_BIO_CHECK_INTERVAL = 12 * 3600   # 12 hours in seconds


def _is_free_user(uid: int) -> bool:
    check_expiry(uid)
    u = get_user(uid)
    return (u.get("plan", "free") if u else "free") == "free"


def _set_hosted_bot_bio(token: str, bio: str) -> bool:
    if not token or ":" not in token:
        return False
    try:
        params = _urlparse.urlencode({"description": bio})
        url = f"https://api.telegram.org/bot{token}/setMyDescription?{params}"
        req = _urlreq.Request(url)
        with _urlreq.urlopen(req, timeout=10) as r:
            result = json.loads(r.read().decode())
        return bool(result.get("ok"))
    except Exception as e:
        log.warning("_set_hosted_bot_bio failed for token %s…: %s",
                    token[:8] if token else "?", e)
        return False


def _get_hosted_bot_bio(token: str) -> Optional[str]:
    if not token or ":" not in token:
        return None
    try:
        url = f"https://api.telegram.org/bot{token}/getMyDescription"
        req = _urlreq.Request(url)
        with _urlreq.urlopen(req, timeout=10) as r:
            result = json.loads(r.read().decode())
        if result.get("ok"):
            return result.get("result", {}).get("description", "")
        return None
    except Exception as e:
        log.warning("_get_hosted_bot_bio failed for token %s…: %s",
                    token[:8] if token else "?", e)
        return None


def set_branding_bio_for_free_bot(bid: str) -> None:
    """
    If the bot belongs to a free-plan user, set the hosted bot's bio
    to the branding text.  Silently does nothing for paid-plan users.
    """
    b = get_bot(bid)
    if not b:
        return
    uid = b.get("user_id")
    if uid is None or not _is_free_user(uid):
        return   # paid plan — leave bio untouched
    token = get_decrypted_bot_token(b)
    if not token:
        return
    ok = _set_hosted_bot_bio(token, HOSTING_BOT_BIO)
    if ok:
        log.info("🌐 Bio set for free-user bot %s (uid=%s)", bid, uid)
    else:
        log.warning("🌐 Bio set FAILED for bot %s (uid=%s)", bid, uid)


async def _bio_enforcer_loop(application) -> None:
    await asyncio.sleep(60)   # wait 1 min after startup before first check
    while True:
        try:
            bots = all_bots()
            for bid, b in bots.items():
                uid = b.get("user_id")
                if uid is None:
                    continue
                if not _is_free_user(uid):
                    continue   # paid plan — skip
                token = get_decrypted_bot_token(b)
                if not token:
                    continue
                current_bio = _get_hosted_bot_bio(token)
                if current_bio is None:
                    continue   # couldn't fetch — skip silently
                if current_bio.strip() != HOSTING_BOT_BIO.strip():
                    ok = _set_hosted_bot_bio(token, HOSTING_BOT_BIO)
                    if ok:
                        log.info("🌐 Bio re-enforced for free-user bot %s (uid=%s)", bid, uid)
                    else:
                        log.warning("🌐 Bio re-enforce FAILED for bot %s (uid=%s)", bid, uid)
        except Exception as e:
            log.warning("_bio_enforcer_loop error: %s", e)
        await asyncio.sleep(_BIO_CHECK_INTERVAL)


#  RAM LIMIT ENFORCER — auto-stops any hosted bot that exceeds the RAM
#  ceiling of its owner's plan, and notifies the owner why.

_RAM_CHECK_INTERVAL = 30   # seconds between RAM sweeps — once a bot is
                           # stopped its status flips off "running", so the
                           # next sweep naturally skips it (no duplicate DMs).

async def _notify_ram_kill(app, bid: str, b: dict, plan_key: str, ram_limit_mb: int, ram_used_mb: float):
    """DM the bot owner that their bot was auto-stopped for exceeding its
    plan's RAM limit, themed to match the bot's other notification cards."""
    pl = PLANS.get(plan_key, PLANS["free"])
    token = get_decrypted_bot_token(b)
    bot_username = await auto_fetch_bot_username(token) if token else ""
    username_line = f"🤖 <b>Bot Username:</b> @{h(bot_username)}\n" if bot_username else ""
    try:
        await app.bot.send_message(
            chat_id=b["user_id"],
            text=(
                f"🚨 <b>Bot Auto-Stopped!</b>\n"
                f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"⛔ <b>Your bot.py has been stopped.</b>\n"
                f"Restart your bot from My Bots\n\n"
                f"⚠️ <b>Reason:</b> Exceeded Plan RAM Limit\n\n"
                f"{pl['emoji']} <b>Your Plan:</b>    <b>{pl['name']}</b>\n"
                f"🧠 <b>RAM Assigned:</b> <code>{ram_limit_mb} MB</code>\n"
                f"📊 <b>RAM Used:</b>     <code>{ram_used_mb:.1f} MB</code>\n"
                f"{username_line}\n"
                f"🚀 <b>Upgrade your plan to get more RAM!</b>"
            ),
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        pass

_ZOMBIE_REAP_INTERVAL = 10   # seconds — how often we sweep for crashed/zombie
                             # hosted-bot processes, independent of whether
                             # any admin/user screen happens to be open.

async def _zombie_reaper_loop(application) -> None:
    """Continuously reaps crashed hosted-bot child processes.

    Without this, a bot that crashes on its own only gets cleaned up the
    next time someone happens to open a screen that calls sync_statuses()
    (My Bots, admin panel, etc.). Until then it sits as a zombie: still
    holding a PID, still marked status='running' in storage, and reporting
    0.0 MB RAM (a zombie's memory has already been released by the kernel).
    This is most likely to bite right after "Start All", since launching
    many bots back-to-back raises the odds one crashes shortly after its
    startup check passes — and previously nothing would notice until an
    admin happened to open the panel again.

    This loop just calls sync_statuses() on a short fixed interval, which
    both reaps the OS-level zombie (via Popen.poll()) and corrects the
    stored status the moment a crash is detected, so bots never sit in an
    undetected zombie state for long.
    """
    await asyncio.sleep(15)   # let startup settle before the first sweep
    while True:
        try:
            sync_statuses()
        except Exception as e:
            log.warning("_zombie_reaper_loop error: %s", e)
        await asyncio.sleep(_ZOMBIE_REAP_INTERVAL)


_AUTO_DELETE_STOPPED_INTERVAL = 3600   # seconds — how often we sweep for
                                        # long-stopped free-plan bots.
_AUTO_DELETE_STOPPED_MIN_DAYS = 7.0    # a bot must be stopped this long
                                        # before the auto-cleanup removes it.

async def _auto_delete_stopped_bots_loop(application) -> None:
    """Free-plan bots that have sat stopped for 7+ days are automatically
    removed (file + DB entry) to reclaim storage. Paid-plan bots are never
    touched by this loop, no matter how long they've been stopped."""
    await asyncio.sleep(120)   # let startup settle before the first sweep
    while True:
        try:
            result = await asyncio.to_thread(
                _delete_stopped_bots_sync, _AUTO_DELETE_STOPPED_MIN_DAYS, True
            )
            if result["deleted"]:
                log.info(
                    "🗑️ Auto-deleted %s free-plan bot(s) stopped ≥%s days",
                    result["deleted"], _AUTO_DELETE_STOPPED_MIN_DAYS,
                )
        except Exception as e:
            log.warning("_auto_delete_stopped_bots_loop error: %s", e)
        await asyncio.sleep(_AUTO_DELETE_STOPPED_INTERVAL)


async def _ram_enforcer_loop(application) -> None:
    await asyncio.sleep(60)   # wait 1 min after startup before first check
    if not _PSUTIL:
        log.warning("_ram_enforcer_loop: psutil unavailable — RAM limit "
                     "enforcement is DISABLED until psutil is fixed.")
    while True:
        try:
            if _PSUTIL:
                for bid, b in list(all_bots().items()):
                    if b.get("status") != "running" or not b.get("pid"):
                        continue
                    uid = b.get("user_id")
                    if uid is None:
                        continue
                    ram_limit_mb = get_ram_limit_mb(int(uid))
                    if ram_limit_mb is None:
                        continue   # unlimited plan — nothing to enforce
                    ram_used_mb = get_bot_ram_mb(bid)
                    if ram_used_mb is None:
                        continue   # couldn't read — skip silently this sweep
                    if ram_used_mb > ram_limit_mb:
                        u = get_user(int(uid))
                        plan_key = (u.get("plan", "free") if u else "free")
                        if plan_key not in PLANS:
                            plan_key = "free"
                        log.warning(
                            "🧠 RAM limit exceeded — stopping bot %s (uid=%s): %.1f MB > %s MB",
                            bid, uid, ram_used_mb, ram_limit_mb,
                        )
                        proc_stop(bid)
                        await _notify_ram_kill(application, bid, b, plan_key, ram_limit_mb, ram_used_mb)
        except Exception as e:
            log.warning("_ram_enforcer_loop error: %s", e)
        await asyncio.sleep(_RAM_CHECK_INTERVAL)


#  EXPIRY WARNING BACKGROUND THREAD

_warned_today: dict = {}
_expired_notified: set = set()

async def _send_expiry_warnings(app):
    while True:
        try:
            today = _now_ist().date().isoformat()
            for uid_s, u in all_users().items():
                expiry = u.get("expiry")
                plan = u.get("plan","free")
                if not expiry or plan in ("free", "lifetime"):
                    continue
                try:
                    exp_date = _parse_dt(expiry)
                    # Use calendar-date subtraction to avoid timedelta.days
                    # returning -1 for sub-day differences (e.g. 23:59 on expiry day).
                    days_left = (exp_date.date() - _now_ist().date()).days
                    # Plan has expired — notify user and reset to free
                    if days_left < 0 and uid_s not in _expired_notified:
                        _expired_notified.add(uid_s)
                        pl = PLANS.get(plan, PLANS["free"])
                        upd_user(int(uid_s), {"plan": "free", "expiry": None})
                        try:
                            await app.bot.send_message(
                                chat_id=int(uid_s),
                                text=(
                                    f"❌ <b>Plan Expired!</b>\n"
                                    f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                                    f"{pl['emoji']} <b>Your {pl['name']} plan has expired.</b>\n\n"
                                    f"Your account has been reset to the 🆓 <b>Free</b> plan.\n\n"
                                    f"<b>Renew your plan to keep your bots running.\n"
                                    f"Contact @{DEVELOPER_USERNAME} for renewal.</b>"
                                ),
                                parse_mode=ParseMode.HTML,
                                reply_markup=InlineKeyboardMarkup([
                                    [InlineKeyboardButton("💰 Renew Plan", callback_data="plans", style="primary")],
                                ]),
                            )
                        except Exception:
                            pass
                    # Plan expiring soon — warn user
                    elif 0 <= days_left <= 3:
                        key = f"{uid_s}_{today}"
                        if key not in _warned_today:
                            _warned_today[key] = True
                            pl = PLANS.get(plan, PLANS["free"])
                            try:
                                await app.bot.send_message(
                                    chat_id=int(uid_s),
                                    text=(
                                        f"⚠️ <b>Plan Expiry Warning!</b>\n"
                                        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                                        f"{pl['emoji']} <b>Plan:</b> <b>{pl['name']}</b>\n"
                                        f"📅 <b>Expires in:</b> <b>{days_left} day(s)</b>\n"
                                        f"🗓 <b>Expiry Date:</b> <code>{exp_date.strftime('%d-%m-%Y')}</code>\n\n"
                                        f"<b>Renew your plan to keep your bots running without interruption.\n"
                                        f"Contact @{DEVELOPER_USERNAME} for renewal.</b>"
                                    ),
                                    parse_mode=ParseMode.HTML,
                                    reply_markup=InlineKeyboardMarkup([
                                        [InlineKeyboardButton("💰 View Plans", callback_data="plans", style="primary")],
                                    ]),
                                )
                            except Exception:
                                pass
                except Exception:
                    pass
        except Exception:
            pass
        await asyncio.sleep(3600)

#  FORCE JOIN CHECK — MULTIPLE CHANNELS

async def _check_user_in_channel(ctx, channel_username: str, uid: int) -> bool:
    # Normalise username
    username = channel_username.strip()
    if not username:
        return True  # Skip empty entries

    # Method 1: Direct HTTP API call — works for public channels without bot membership
    try:
        url = (
            f"https://api.telegram.org/bot{ctx.bot.token}/getChatMember"
            f"?chat_id={_urlparse.quote(username)}&user_id={uid}"
        )
        req = _urlreq.Request(url)
        with _urlreq.urlopen(req, timeout=10) as r:
            body = r.read().decode("utf-8", errors="ignore")
        result = json.loads(body)
        if result.get("ok"):
            status = result.get("result", {}).get("status", "")
            return status in ("member", "administrator", "creator")
        # If API says the user is "left" or "kicked" — blocked
        error_code = result.get("error_code", 0)
        # 400 = bad request (user never interacted), treat as not joined
        # 403 = bot not in channel — fall through to method 2
        if error_code == 403:
            raise Exception("bot not in channel, try method 2")
        return False
    except Exception as _e1:
        # Method 2: python-telegram-bot wrapper (needs bot to be member for private channels)
        try:
            member = await ctx.bot.get_chat_member(chat_id=username, user_id=uid)
            return member.status in ("member", "administrator", "creator")
        except Exception:
            # If both fail (e.g. private channel and bot not a member), let user through
            return True

async def check_force_join(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> bool:
    """Returns True if user is OK (joined all channels or force-join off). Returns False if blocked."""
    uid = update.effective_user.id
    if uid == OWNER_ID:
        return True
    fj = get_setting("force_join", False)
    if not fj:
        return True
    channels = get_force_join_channels()
    if not channels:
        return True

    # Check which channels user has NOT joined
    not_joined = []
    for ch in channels:
        username = ch.get("username", "")
        if not username:
            continue
        is_member = await _check_user_in_channel(ctx, username, uid)
        if not is_member:
            not_joined.append(ch)

    if not not_joined:
        return True

    # Build polite force-join message (stylized font, no extra HTML bold)
    _fj_name = h(update.effective_user.first_name or "there")
    msg = (
        f"👋 𝑾𝒆𝒍𝒄𝒐𝒎𝒆 𝑩𝒂𝒄𝒌, {_fj_name}!\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n\n"
        f"📢 𝒀𝒐𝒖 𝑴𝒖𝒔𝒕 𝑱𝒐𝒊𝒏 𝑶𝒖𝒓 𝑹𝒆𝒒𝒖𝒊𝒓𝒆𝒅 𝑪𝒉𝒂𝒏𝒏𝒆𝒍𝒔 𝑻𝒐 𝑼𝒔𝒆 𝑻𝒉𝒊𝒔 𝑩𝒐𝒕.\n\n"
        f"👇 𝑪𝒍𝒊𝒄𝒌 𝑻𝒉𝒆 𝑩𝒖𝒕𝒕𝒐𝒏𝒔 𝑩𝒆𝒍𝒐𝒘 𝑻𝒐 𝑱𝒐𝒊𝒏, 𝑻𝒉𝒆𝒏 𝑻𝒂𝒑 ✅ 𝑽𝒆𝒓𝒊𝒇𝒚."
    )

    # Build 2×2 grid of channel buttons
    kb_rows = []
    row = []
    for ch in not_joined:
        username = ch.get("username", "")
        link = ch.get("link", "")
        title = ch.get("title", username if username else "Channel")
        if not link and username:
            link = f"https://t.me/{username.lstrip('@')}"
        row.append(InlineKeyboardButton(f"{title}", url=link, style="primary"))
        if len(row) == 2:
            kb_rows.append(row)
            row = []
    if row:  # leftover odd button — center it alone
        kb_rows.append(row)
    kb_rows.append([InlineKeyboardButton("✅ I Have Joined — Verify Now", callback_data="fj_verify", style="success")])
    kb = InlineKeyboardMarkup(kb_rows)

    if update.message:
        await update.message.reply_text(msg, parse_mode=ParseMode.HTML, reply_markup=kb)
    elif update.callback_query:
        await update.callback_query.answer("Please join our channels first!", show_alert=True)
        try:
            await update.callback_query.edit_message_text(msg, parse_mode=ParseMode.HTML, reply_markup=kb)
        except Exception:
            try:
                await update.callback_query.message.reply_text(msg, parse_mode=ParseMode.HTML, reply_markup=kb)
            except Exception:
                pass
    return False

async def cb_fj_verify(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    uid = update.effective_user.id

    if is_banned(uid):
        await q.answer()
        try:
            await q.edit_message_text("<b>🚫 You're Banned</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>You no longer have access to this bot.</b>", parse_mode=ParseMode.HTML)
        except Exception:
            try:
                await q.message.reply_text("<b>🚫 You're Banned</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>You no longer have access to this bot.</b>", parse_mode=ParseMode.HTML)
            except Exception:
                pass
        return

    await q.answer("Verifying your membership…")

    fj = get_setting("force_join", False)
    if not fj:
        await cmd_start(update, ctx)
        return

    channels = get_force_join_channels()
    not_joined = []
    for ch in channels:
        username = ch.get("username", "")
        if not username:
            continue
        is_member = await _check_user_in_channel(ctx, username, uid)
        if not is_member:
            not_joined.append(ch)

    if not_joined:
        ch_list = "\n".join(f"• {ch.get('title', ch.get('username',''))}" for ch in not_joined)
        msg = (
            f"⚠️ 𝑪𝒉𝒂𝒏𝒏𝒆𝒍 𝑱𝒐𝒊𝒏 𝑹𝒆𝒒𝒖𝒊𝒓𝒆𝒅\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈\n\n"
            f"📢 𝑷𝒍𝒆𝒂𝒔𝒆 𝑱𝒐𝒊𝒏 𝑨𝒍𝒍 𝑹𝒆𝒒𝒖𝒊𝒓𝒆𝒅 𝑪𝒉𝒂𝒏𝒏𝒆𝒍𝒔 𝑭𝒊𝒓𝒔𝒕.\n"
            f"<b>{h(ch_list)}</b>\n\n"
            f"👇 𝑱𝒐𝒊𝒏 𝑩𝒆𝒍𝒐𝒘, 𝑻𝒉𝒆𝒏 𝑻𝒂𝒑 ✅ 𝑽𝒆𝒓𝒊𝒇𝒚."
        )
        kb_rows = []
        row = []
        for ch in not_joined:
            username = ch.get("username", "")
            link = ch.get("link", "")
            title = ch.get("title", username if username else "Channel")
            if not link and username:
                link = f"https://t.me/{username.lstrip('@')}"
            row.append(InlineKeyboardButton(f"{title}", url=link, style="primary"))
            if len(row) == 2:
                kb_rows.append(row)
                row = []
        if row:
            kb_rows.append(row)
        kb_rows.append([InlineKeyboardButton("✅ I Have Joined — Verify Now", callback_data="fj_verify", style="success")])
        try:
            await q.edit_message_text(msg, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(kb_rows))
        except Exception:
            pass
        return

    # All joined — proceed to start
    await cmd_start(update, ctx)

#  UI HELPERS

def fmt_expiry(e: Optional[str]) -> str:
    if not e:
        return "♾️ Never"
    try:
        return _parse_dt(e).strftime("%d-%m-%Y")
    except Exception:
        return h(e)

def fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:    parts.append(f"{days}d")
    if hours or days:   parts.append(f"{hours}h")
    if minutes or hours or days: parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)

def bot_uptime(b: dict) -> str:
    started = b.get("started_at")
    if not started or b.get("status") != "running":
        return "Not running"
    try:
        return fmt_duration((_now_ist() - _parse_dt(started)).total_seconds())
    except Exception:
        return "Unknown"

def safe_filename(name: str) -> str:
    base = os.path.basename(name or "bot.py")
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    return base or "bot.py"

def file_ext(name: str) -> str:
    return os.path.splitext(name or "")[1].lower()

def is_allowed_file(name: str) -> bool:
    return file_ext(name) in ALLOWED_EXTENSIONS

def remove_bot_file(b: dict):
    fp = b.get("file_path","")
    # Remove stored file — could be plaintext or .enc
    for candidate in [fp, fp + ".enc", fp[:-4] if fp.endswith(".enc") else None]:
        if candidate and os.path.exists(candidate):
            try:
                os.remove(candidate)
            except Exception:
                pass
    folder = os.path.dirname(fp)
    try:
        if folder and os.path.basename(folder) == b.get("bot_id") and not os.listdir(folder):
            os.rmdir(folder)
    except Exception:
        pass

def user_display(uid: str, user: Optional[dict] = None) -> str:
    user = user or get_user(int(uid)) or {}
    username = (user.get("username") or "").strip()
    if username:
        return f"@{username}"
    first = (user.get("first_name") or "").strip()
    if first:
        return f"{first} ({uid})"
    return f"User ({uid})"

def pending_bots() -> list:
    return [b for b in all_bots().values() if b.get("pending")]

def start_command_for_file(fp: str) -> Tuple[Optional[list], Optional[str]]:
    ext = file_ext(fp)
    if ext == ".py":
        return [sys.executable, fp], None
    return None, f"Unsupported file type: {ext}"

def si(status: str) -> str:
    if status == "running":
        return "🟢 <b>Running</b>"
    elif status == "error":
        return "🟡 <b>Error In File</b>"
    elif status == "manually_stopped":
        return "🔴 <b>Stopped</b>"
    else:
        return "🔴 <b>Off</b>"

def _status_dot_plain(status: str) -> str:
    """Plain (non-HTML) version of si(), for use inside MarkdownV2 messages."""
    if status == "running":
        return "🟢 Running"
    elif status == "error":
        return "🟡 Error"
    elif status == "manually_stopped":
        return "🔴 Stopped"
    else:
        return "🔴 Off"

def gen_code() -> str:
    a = "".join(random.choices(string.ascii_uppercase + string.digits, k=3))
    b = "".join(random.choices(string.ascii_uppercase + string.digits, k=5))
    return f"UNX-{a}-{b}"

def storage_bar(used: int, lim: int, unlimited: bool = False) -> str:
    """Generate a rich visual storage bar. Fully crash-safe."""
    try:
        used = max(0, int(used or 0))
        if unlimited:
            return (
                f"♾️ <b>Storage:</b>  <code>UNLIMITED</code>\n"
                f"📂 <b>Files Used:</b> <b>{used}</b>  —  <b>No limit on your plan</b>"
            )
        lim = max(0, int(lim or 0))
        if lim == 0:
            return f"📁 <b>Storage:</b> <code>{used} / 0</code>  —  <b>No slots available</b>"
        pct      = min(used / lim, 1.0)
        bar_len  = 15
        filled   = int(round(pct * bar_len))
        empty    = bar_len - filled
        bar      = "▰" * filled + "▱" * empty
        pct_disp = int(pct * 100)
        if pct_disp < 50:
            badge = "🟢 Good"
        elif pct_disp < 80:
            badge = "🟡 Getting Full"
        else:
            badge = "🔴 Almost Full"
        return (
            f"📁 <b>Storage</b>  ·  {badge}\n"
            f"<code>{bar}</code>  <b>{pct_disp}%</b>\n"
            f"<b>{used}</b> / <b>{lim}</b> files used"
        )
    except Exception:
        return f"📁 <b>Storage:</b> <code>{used or 0} / {lim or 0}</code>"

#  KEYBOARDS

def kb_main() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Upload Bot",    callback_data="upload", style="success"),
         InlineKeyboardButton("🤖 My Bots",        callback_data="mybots", style="success")],
        [InlineKeyboardButton("💰 Plans",          callback_data="plans", style="primary"),
         InlineKeyboardButton("🎫 Redeem Code",    callback_data="redeem", style="primary")],
        [InlineKeyboardButton("⚙️ Pip Management", callback_data="pip_management", style="primary"),
         InlineKeyboardButton("⏱️ Bot Uptime",     callback_data="bot_uptime", style="primary")],
        [InlineKeyboardButton("❓ Help",            callback_data="help", style="primary"),
         InlineKeyboardButton("📊 Stats",           callback_data="user_stats", style="primary")],
        [InlineKeyboardButton("💭 Developer",       url=f"https://t.me/{DEVELOPER_USERNAME}", style="danger")],
    ])

def kb_back(cb: str = "home") -> InlineKeyboardMarkup:
    label = "🏠 Home" if cb == "home" else "🔙 Back"
    return InlineKeyboardMarkup([[InlineKeyboardButton(label, callback_data=cb, style="primary")]])

def kb_admin() -> InlineKeyboardMarkup:
    # Colour pattern (repeats every 6 rows, in order): blue, blue, green,
    # green, red, red — then back to blue for the next 6 rows, and so on,
    # applied to every row of the admin panel.
    _PATTERN = ["primary", "primary", "success", "success", "danger", "danger"]
    rows_spec = [
        [("📊 Stats",            "adm_stats"),
         ("⚡ Running Bots",     "adm_running")],
        [("🧰 Bots Management",  "adm_bot_mgmt"),
         ("⏳ Pending Approvals", "adm_pending")],
        [("👥 Users",             "adm_users_menu"),
         ("🔎 Find User",         "adm_find_user_id")],
        [("🆕 Add Users",         "adm_add_users"),
         ("🗑️ Delete Users",      "adm_delete_users")],
        [("🔄 Auto Fetch Users",  "adm_auto_fetch"),
         ("📥 Fetch HB Users",   "adm_fetch_hb_users")],
        [("🗂️ User Files",        "adm_files_pick"),
         ("💾 Save File",         "adm_save_file_pick")],
        [("🚫 Ban User",          "adm_ban"),
         ("♻️ Unban User",         "adm_unban")],
        [("🔐 Force Join",        "adm_force_join"),
         ("🔁 Approval Toggle",   "adm_approval_toggle")],
        [("🎁 Give Sub",          "adm_give_sub"),
         ("💳 Payments",          "adm_payments")],
        [("💎 Create Code",       "adm_create_code"),
         ("🌟 New Plan",          "adm_new_plan")],
        [("👑 Manage Plans",      "adm_manage_plans"),
         ("🧠 Custom RAM",        "adm_custom_ram")],
        [("📢 Broadcast",         "adm_broadcast"),
         ("📡 Bot Broadcast",     "adm_bot_broadcast")],
        [("🗑️ Del Broadcast",     "adm_del_broadcast"),
         ("📋 Failed BC List",    "adm_failed_bc_list")],
        [("🖼️ Set QR",            "adm_set_qr"),
         ("🏦 Set UPI",           "adm_set_upi")],
        [("⏲️ Custom Uptime",      "adm_set_custom_uptime")],
        [("📦 Generate Backup",   "adm_gen_backup"),
         ("📤 Upload Backup",     "adm_upload_backup")],
    ]
    # Row-specific colour overrides: the 6-row repeating pattern above
    # gets this one row wrong (Broadcast / Bot Broadcast should be blue,
    # matching Del Broadcast below it, not red).
    _COLOUR_OVERRIDES = {11: "primary"}  # row index -> style

    kb_rows = []
    for i, row_spec in enumerate(rows_spec):
        colour = _COLOUR_OVERRIDES.get(i, _PATTERN[i % len(_PATTERN)])
        kb_rows.append([
            InlineKeyboardButton(label, callback_data=cb, style=colour)
            for label, cb in row_spec
        ])
    return InlineKeyboardMarkup(kb_rows)

def kb_admin_bot_mgmt() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("▶️ Start All", callback_data="adm_start_all", style="success"),
         InlineKeyboardButton("❌ Stop All",  callback_data="adm_stop_all", style="danger")],
        [InlineKeyboardButton("🟢 Running Bots",  callback_data="adm_running", style="primary"),
         InlineKeyboardButton("🔴 Stopped Bots",  callback_data="adm_stopped_bots", style="primary")],
        [InlineKeyboardButton("🟡 Error Bots",    callback_data="adm_error_bots", style="primary"),
         InlineKeyboardButton("📂 User Files",    callback_data="adm_files_pick", style="primary")],
        [InlineKeyboardButton("🔒 Security Blocked", callback_data="adm_security_bots", style="primary")],
        [InlineKeyboardButton("🗑️ Delete Error Files", callback_data="adm_del_error_files", style="danger"),
         InlineKeyboardButton("🗑️ Delete Stopped Bots", callback_data="adm_del_stopped_bots", style="danger")],
        [InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")],
    ])

def kb_bot(bid: str, status: str, back: str = "mybots") -> InlineKeyboardMarkup:
    if status == "running":
        ctrl_row = [
            InlineKeyboardButton("❌ Stop",    callback_data=f"bact_stop_{bid}", style="danger"),
            InlineKeyboardButton("🔄 Restart", callback_data=f"bact_restart_{bid}", style="primary"),
        ]
    else:
        ctrl_row = [
            InlineKeyboardButton("▶️ Start",   callback_data=f"bact_start_{bid}", style="success"),
            InlineKeyboardButton("🔄 Restart", callback_data=f"bact_restart_{bid}", style="primary"),
        ]
    return InlineKeyboardMarkup([
        ctrl_row,
        [InlineKeyboardButton("📋 Logs",         callback_data=f"bact_logs_{bid}", style="primary"),
         InlineKeyboardButton("💾 Save",          callback_data=f"bact_save_{bid}", style="success")],
        [InlineKeyboardButton("🔁 Replace File",  callback_data=f"bact_replace_{bid}", style="primary"),
         InlineKeyboardButton("👤 Transfer",      callback_data=f"bact_transfer_{bid}", style="primary")],
        [InlineKeyboardButton("🗑️ Delete",         callback_data=f"bact_delete_{bid}", style="danger"),
         InlineKeyboardButton("🔙 Back",           callback_data=back, style="primary")],
    ])

async def _edit_or_resend(q, text: str, reply_markup=None, parse_mode=ParseMode.HTML):
    """
    Edit a callback query's message in place, unless that message is a
    photo (e.g. the payment QR code) — Telegram forbids turning a photo
    message into a text message via edit_message_text. In that case,
    delete the photo message and send a fresh text message instead so
    navigation (like Cancel/Back) always works from a QR screen.
    """
    if q.message and q.message.photo:
        try:
            await q.message.reply_text(text, parse_mode=parse_mode, reply_markup=reply_markup)
        finally:
            try:
                await q.delete_message()
            except Exception:
                pass
        return
    try:
        await q.edit_message_text(text, parse_mode=parse_mode, reply_markup=reply_markup)
    except BadRequest as e:
        if "not modified" in str(e).lower():
            return
        await q.message.reply_text(text, parse_mode=parse_mode, reply_markup=reply_markup)
        try:
            await q.delete_message()
        except Exception:
            pass

#  STATE MACHINE

def set_st(ctx, state: str, **kw):
    ctx.user_data.clear()
    ctx.user_data["_s"] = state
    ctx.user_data.update(kw)

def get_st(ctx) -> str:
    return ctx.user_data.get("_s","")

def clr_st(ctx):
    ctx.user_data.clear()

#  /start & HOME

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if is_banned(u.id):
        if update.message:
            await update.message.reply_text("<b>🚫 You're Banned</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>You no longer have access to this bot.</b>", parse_mode=ParseMode.HTML)
        return
    if not await check_force_join(update, ctx):
        return
    full_name = " ".join(x for x in [u.first_name, u.last_name] if x) or "N/A"
    is_new_user = get_user(u.id) is None
    ensure_user(u.id, u.username or "", u.first_name or "")
    if is_new_user:
        username = f"@{u.username}" if u.username else "N/A"
        alert = (
            "<blockquote>"
            f"<b>👤 New User Alert 𖤐\n"
            f"┣ ✦ Nᴀᴍᴇ : {h(full_name)}\n"
            f"┣ ✦ Uꜱᴇʀɴᴀᴍᴇ : {h(username)}\n"
            f"┗ ✦ Uꜱᴇʀ Iᴅ : <code>{u.id}</code></b>"
            "</blockquote>"
        )
        for admin_id in ADMIN_IDS:
            try:
                await ctx.bot.send_message(chat_id=admin_id, text=alert, parse_mode=ParseMode.HTML)
            except Exception:
                pass

    check_expiry(u.id)
    clr_st(ctx)
    usr = get_user(u.id) or {"plan":"free","expiry":None,"bots":[]}
    p = usr.get("plan","free")
    if p not in PLANS:
        p = "free"
    pl   = PLANS[p]
    unlimited = pl["file_limit"] == UNLIMITED_SENTINEL
    lim  = get_file_limit(u.id)
    used = bot_count(u.id)

    # Storage bar
    if unlimited:
        s_bar = storage_bar(used, lim, unlimited=True)
    else:
        s_bar = storage_bar(used, lim)

    expiry_str = fmt_expiry(usr.get("expiry"))

    # Compute file percentage for display
    if unlimited:
        _files_line = f"📦 Files : {used}/♾️"
    elif lim > 0:
        _pct = int(min(used / lim, 1.0) * 100)
        _files_line = f"📦 Files : {used}/{lim} ({_pct}%)"
    else:
        _files_line = f"📦 Files : {used}/0"

    text = (
        f"<b>╭━〔 🌐 UnknownXHosting 〕━╮ㅤ</b>\n\n"
        f"<b>👤 Name     :</b> <b>{h(full_name)}</b>\n"
        f"<b>🆔 User ID  :</b> <b><code>{u.id}</code></b>\n"
        f"<b>🍁 Plan     :</b> <b>{pl.get('emoji','📦')} {pl['name']}</b>\n"
        f"<b>📅 Expiry   :</b> <b><code>{expiry_str}</code></b>\n\n"
        f"<b>📁 Storage Used</b>\n"
        f"{s_bar}\n\n"
        f"<b>{_files_line}</b>\n\n"
        f"<b>🚀 Enjoy your hosting experience!</b>\n"
        f"<b>Use Buttons Below 👇</b>"
    )
    if update.message:
        await update.message.reply_text(text, reply_markup=kb_main(), parse_mode=ParseMode.HTML)
    else:
        try:
            await update.callback_query.edit_message_text(text, reply_markup=kb_main(), parse_mode=ParseMode.HTML)
        except Exception:
            await update.callback_query.message.reply_text(text, reply_markup=kb_main(), parse_mode=ParseMode.HTML)

async def cb_home(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.answer()
    clr_st(ctx)
    await cmd_start(update, ctx)

#  PROFILE PAGE

def _build_profile_text(uid: int, full_name: str) -> str:
    check_expiry(uid)
    usr = get_user(uid) or {"plan": "free", "expiry": None, "bots": []}
    plan_key = usr.get("plan", "free")
    if plan_key not in PLANS:
        plan_key = "free"
    pl = PLANS[plan_key]

    # Expiry line — append days-remaining for paid, non-lifetime plans.
    raw_expiry = usr.get("expiry")
    expiry_str = fmt_expiry(raw_expiry)
    if raw_expiry and plan_key not in ("free", "lifetime"):
        try:
            days_left = (_parse_dt(raw_expiry).date() - _now_ist().date()).days
            if days_left >= 0:
                expiry_str = f"{expiry_str} ({days_left} day{'s' if days_left != 1 else ''} left)"
        except Exception:
            pass

    # RAM line — show the admin's custom override (with a note) if one is
    # set on this user, otherwise fall back to the plan's default RAM cap.
    custom_ram = usr.get("custom_ram_mb")
    if custom_ram is not None:
        ram_cap_val = custom_ram
        ram_str = "Unlimited ♾️" if custom_ram == UNLIMITED_SENTINEL else f"{custom_ram} MB"
        ram_line = f"<b>🧠 Ram Allowed :</b> <b>{ram_str}</b> <b>(custom)</b>"
    else:
        ram_cap_val = pl.get("ram_mb", 0)
        ram_str = "Unlimited ♾️" if ram_cap_val == UNLIMITED_SENTINEL else f"{ram_cap_val} MB"
        ram_line = f"<b>🧠 Ram Allowed :</b> <b>{ram_str}</b> <b>({pl['name']} plan)</b>"

    lim = get_file_limit(uid)
    used = bot_count(uid)
    unlimited_files = pl.get("file_limit", 0) == UNLIMITED_SENTINEL
    files_str = f"{used}/♾️" if unlimited_files else f"{used}/{lim}"

    member_since = usr.get("member_since") or "Unknown"

    sync_statuses()
    bots = user_bots(uid)
    running  = [b for b in bots if b.get("status") == "running"]
    stopped  = [b for b in bots if b.get("status") == "stopped"]
    errored  = [b for b in bots if b.get("status") not in ("running", "stopped")]

    # Live RAM usage total across running bots, vs. the plan/custom cap.
    ram_used_total = 0.0
    ram_used_known = True
    for b in running:
        v = get_bot_ram_mb(b["bot_id"])
        if v is None:
            ram_used_known = False
        else:
            ram_used_total += v
    if ram_used_known and running:
        ram_cap_str = "♾️" if ram_cap_val == UNLIMITED_SENTINEL else f"{ram_cap_val} MB"
        ram_used_line = f"<b>📊 Ram Used    :</b> <b>{ram_used_total:.1f} MB / {ram_cap_str}</b>"
    else:
        ram_used_line = None

    lines = [
        "<b>👤 Your Profile</b>",
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈",
        f"<b>👤 Name        :</b> <b>{h(full_name)}</b>",
        f"<b>🆔 User ID     :</b> <b><code>{uid}</code></b>",
        f"<b>🍁 Plan        :</b> <b>{pl.get('emoji','📦')} {pl['name']}</b>",
        f"<b>📅 Expiry      :</b> <b><code>{expiry_str}</code></b>",
        ram_line,
    ]
    if ram_used_line:
        lines.append(ram_used_line)
    lines.append(f"<b>📦 Files       :</b> <b>{files_str}</b>")
    lines.append(f"<b>🗓 Member Since:</b> <b>{h(member_since)}</b>")
    lines.append("")
    lines.append(f"<b>🤖 Your Bots ({len(bots)} total)</b>")
    lines.append("┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈")
    lines.append(f"🟢 Running : {len(running)}")
    lines.append(f"🔴 Stopped : {len(stopped)}")
    lines.append(f"🟡 Error   : {len(errored)}")
    lines.append("")

    if running:
        for b in running:
            ram_mb = get_bot_ram_mb(b["bot_id"])
            ram_disp = f"{ram_mb:.1f} MB" if ram_mb is not None else "N/A"
            uname = b.get("project_name") or b.get("file_name", "bot")
            lines.append(f"🟢 @{h(uname)} — {ram_disp} • ⏱ {h(bot_uptime(b))}")
    else:
        lines.append("<b>No bots currently running.</b>")

    return "\n".join(lines)


def _kb_profile(uid: int) -> InlineKeyboardMarkup:
    # Always a 2x2 grid — the bottom-left slot swaps between a generic
    # "Plans" link and an urgent "Renew Plan" prompt depending on expiry.
    usr = get_user(uid) or {}
    plan_key = usr.get("plan", "free")
    raw_expiry = usr.get("expiry")
    bottom_left = InlineKeyboardButton("💰 Plans", callback_data="plans", style="primary")
    if raw_expiry and plan_key not in ("free", "lifetime"):
        try:
            days_left = (_parse_dt(raw_expiry).date() - _now_ist().date()).days
            if 0 <= days_left <= 7:
                bottom_left = InlineKeyboardButton("💰 Renew Plan", callback_data="plans", style="primary")
        except Exception:
            pass
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 Refresh", callback_data="profile_refresh", style="primary"),
         InlineKeyboardButton("🤖 My Bots", callback_data="mybots", style="primary")],
        [bottom_left,
         InlineKeyboardButton("🏠 Home", callback_data="home", style="primary")],
    ])


async def cmd_profile(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    if is_banned(u.id):
        if update.message:
            await update.message.reply_text("<b>🚫 You're Banned</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>You no longer have access to this bot.</b>", parse_mode=ParseMode.HTML)
        return
    if not await check_force_join(update, ctx):
        return
    full_name = " ".join(x for x in [u.first_name, u.last_name] if x) or "N/A"
    ensure_user(u.id, u.username or "", u.first_name or "")
    text = _build_profile_text(u.id, full_name)
    if update.message:
        await update.message.reply_text(
            text, reply_markup=_kb_profile(u.id), parse_mode=ParseMode.HTML,
            reply_to_message_id=update.message.message_id,
        )
    else:
        try:
            await update.callback_query.edit_message_text(text, reply_markup=_kb_profile(u.id), parse_mode=ParseMode.HTML)
        except Exception:
            await update.callback_query.message.reply_text(text, reply_markup=_kb_profile(u.id), parse_mode=ParseMode.HTML)


async def cb_profile_refresh(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.answer("Refreshed ✅")
    u = update.effective_user
    full_name = " ".join(x for x in [u.first_name, u.last_name] if x) or "N/A"
    text = _build_profile_text(u.id, full_name)
    try:
        await update.callback_query.edit_message_text(text, reply_markup=_kb_profile(u.id), parse_mode=ParseMode.HTML)
    except BadRequest as e:
        if "not modified" not in str(e).lower():
            raise

#  PLANS PAGE

async def cb_plans(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    qr_set = bool(get_setting("payment_qr",""))
    buy_row = [[InlineKeyboardButton("💳 Buy a Plan", callback_data="plans_buy", style="success")]] if qr_set else []
    all_pl = get_all_plans()

    def _price_sort_key(item):
        pk, pl = item
        if pk == "free":
            return -1
        price_str = pl.get("price", "")
        m = re.search(r"[\d,]+", price_str.replace(",", ""))
        try:
            return float(m.group().replace(",", "")) if m else 9999999
        except Exception:
            return 9999999

    sorted_plans = sorted(all_pl.items(), key=_price_sort_key)
    blocks = []
    for pk, pl in sorted_plans:
        emoji = pl.get("emoji", "📦")
        name = pl.get("name", pk)
        price = pl.get("price", "N/A")
        lim = pl.get("file_limit", 0)
        runs = pl.get("run_limit", 0)
        ram = pl.get("ram_mb", 0)
        if lim == UNLIMITED_SENTINEL or runs == UNLIMITED_SENTINEL or ram == UNLIMITED_SENTINEL:
            detail = "Unlimited everything, forever"
        else:
            ram_str = f"{ram/1024:g}GB" if ram >= 1024 else f"{ram}MB"
            detail = f"{lim} files · {runs} bots · {ram_str} RAM"
        blocks.append(
            f"{emoji} <b>{name}</b> — <b>{price}</b>\n"
            f"   └ {detail}"
        )

    plan_text = "\n\n".join(blocks)
    await _edit_or_resend(
        q,
        "💰 <b>Hosting Plans</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n\n"
        f"{plan_text}\n\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>Tap 💳 Buy a Plan below, or message @{DEVELOPER_USERNAME}</b>",
        reply_markup=InlineKeyboardMarkup([
            *buy_row,
            [InlineKeyboardButton("🏠 Home", callback_data="home", style="primary")],
        ]),
        parse_mode=ParseMode.HTML,
    )

async def cb_plans_buy(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    all_pl = get_all_plans()

    def _price_sort_key_buy(item):
        pk, pl = item
        if pk == "free":
            return 9999999  # hide free from buy list
        price_str = pl.get("price", "")
        m = re.search(r"[\d,]+", price_str.replace(",", ""))
        try:
            return float(m.group().replace(",", "")) if m else 9999998
        except Exception:
            return 9999998

    sorted_plans = sorted(
        [(pk, pl) for pk, pl in all_pl.items() if pk != "free"],
        key=_price_sort_key_buy,
    )
    rows = []
    for pk, pl in sorted_plans:
        rows.append([InlineKeyboardButton(f"{pl['emoji']} {pl['name']} — {pl['price']}", callback_data=f"buy_plan_{pk}", style="success")])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="plans", style="primary")])
    clr_st(ctx)  # leaving any in-progress payment (e.g. cancelling from the QR screen)
    await _edit_or_resend(
        q,
        "💳 <b>Select Plan to Purchase</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "<b>Select your desired plan below:</b>",
        reply_markup=InlineKeyboardMarkup(rows),
        parse_mode=ParseMode.HTML,
    )

async def cb_buy_plan(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    plan_key = q.data.split("buy_plan_",1)[1]
    all_pl = get_all_plans()
    if plan_key not in all_pl:
        await q.answer("Invalid plan.", show_alert=True)
        return
    pl = all_pl[plan_key]
    qr_path = get_setting("payment_qr","")
    upi_id  = get_setting("payment_upi","").strip()
    set_st(ctx, "awaiting_payment_ss", payment_plan=plan_key)
    upi_line = f"📲 <b>UPI ID:</b> <code>{h(upi_id)}</code>\n\n" if upi_id else ""
    duration_note = "<b>(One-time payment — no renewal ever)</b>" if plan_key == "lifetime" else ""
    caption = (
        f"💳 <b>Payment — {pl['emoji']} {pl['name']}</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"💰 <b>Amount:</b> <b>{pl['price']}</b> {duration_note}\n\n"
        f"{upi_line}"
        f"<b>Steps:</b>\n"
        f"1️⃣ Scan the QR code and pay <b>{pl['price']}</b>"
        + (f"\n   <b>or pay to UPI: <code>{h(upi_id)}</code></b>" if upi_id else "") +
        f"\n2️⃣ Take a screenshot of your payment\n"
        f"3️⃣ Send the screenshot here\n\n"
        f"<b>Your payment will be verified by the owner and your plan will be activated.</b>"
    )
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="plans_buy", style="danger")]])
    if qr_path and os.path.exists(qr_path):
        try:
            with open(qr_path,"rb") as f:
                await q.message.reply_photo(photo=f, caption=caption, parse_mode=ParseMode.HTML, reply_markup=kb)
            await q.delete_message()
            return
        except Exception:
            pass
    await q.edit_message_text(caption, parse_mode=ParseMode.HTML, reply_markup=kb)

#  REDEEM

async def cb_redeem(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "redeem")
    await q.edit_message_text(
        "🎫 <b>Redeem Premium Code</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "📩 <b>Send your code below.</b>\n"
        "<b>Example: <code>UNX-ABC-12345</code></b>\n\n"
        f"<b>Don't have one? Contact @{DEVELOPER_USERNAME}</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="home", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )

#  HELP

async def cb_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    await q.edit_message_text(
        "❓ <b>How to Use UnknownXHosting</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "🚀 <b>Getting Started</b>\n"
        "   └ Tap <b>➕ Upload Bot</b> to upload your bot file.\n"
        "   └ Supported: <code>.py</code> only\n"
        "   └ Maximum file size: <b>25 MB</b>\n\n"
        "🤖 <b>Managing Your Bots</b>\n"
        "   └ Tap <b>🤖 My Bots</b> to see all your uploaded files.\n"
        "   └ Use <b>▶️ Start</b>, <b>❌ Stop</b>, <b>🔄 Restart</b> buttons.\n"
        "   └ View <b>📋 Logs</b> for any errors.\n"
        "   └ Use <b>👤 Transfer</b> to transfer ownership.\n\n"
        "📦 <b>Installing Packages</b>\n"
        "   └ Tap <b>📦 Install Pip</b> to install Python packages.\n"
        "   └ You can send just the name: <code>requests</code>\n"
        "   └ Or full pip command: <code>pip install requests</code>\n\n"
        "💰 <b>Plans &amp; Upgrade</b>\n"
        "   └ Free plan: 2 files, 2 running bots.\n"
        "   └ Lifetime plan: ♾️ Unlimited files, forever.\n"
        "   └ Tap <b>💰 Plans</b> to see all paid plans.\n"
        "   └ Use <b>🎫 Redeem Code</b> to activate a plan.\n\n"
        "🎫 <b>Redeem Code</b>\n"
        "   └ Get a code from the admin/owner.\n"
        "   └ Codes have a usage limit — once it hits the max, it expires.\n\n"
        "⏳ <b>Approval (Free Users)</b>\n"
        "   └ Free users need owner approval before their bot can run.\n"
        "   └ You'll be notified once approved or rejected.\n\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>Need help? Contact @{DEVELOPER_USERNAME}</b>",
        reply_markup=kb_back("home"),
        parse_mode=ParseMode.HTML,
    )

#  BOT UPTIME / STATS (User)

async def cb_bot_uptime(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    sync_statuses()
    real_uptime = fmt_duration((_now_ist() - START_TIME).total_seconds())
    custom_uptime = get_setting("custom_uptime","").strip()
    # If the admin set a custom uptime value, it REPLACES the real computed
    # main-bot uptime shown to users (instead of just being an extra line).
    uptime = custom_uptime if custom_uptime else real_uptime
    uid = update.effective_user.id
    bots = user_bots(uid)
    running = [b for b in bots if _live_status(b) == "running"]
    lines = []
    for b in running[:10]:
        proc_info = get_bot_proc_info(b["bot_id"])
        line = f"🟢 <code>{h(b['file_name'])}</code> — <b>{h(bot_uptime(b))}</b>"
        if proc_info.get("ram"):
            line += f" | <b>RAM: {h(proc_info['ram'])}</b>"
        lines.append(line)
    user_part = "\n".join(lines) if lines else "<b>No running bots.</b>"
    await q.edit_message_text(
        f"⏱️ <b>Bot Uptime &amp; Stats</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"🌐 <b>Main bot uptime:</b> <code>{h(uptime)}</code>\n\n"
        f"<b>Your running bots:</b>\n{user_part}",
        reply_markup=kb_back("home"),
        parse_mode=ParseMode.HTML,
    )

async def cb_user_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    sync_statuses()
    uid = update.effective_user.id
    check_expiry(uid)
    usr = get_user(uid) or {}
    bots = user_bots(uid)
    running = [b for b in bots if _live_status(b) == "running"]
    plan = usr.get("plan","free")
    if plan not in PLANS:
        plan = "free"
    pl = PLANS[plan]
    sys_info = get_system_stats()
    lines = [
        f"📊 <b>Your Stats</b>",
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈",
        f"",
        f"👤 <b>Plan:</b> {pl['emoji']} <b>{pl['name']}</b>",
        f"📁 <b>Files uploaded:</b> <b>{len(bots)}</b>",
        f"🟢 <b>Running bots:</b> <b>{len(running)}</b>",
        f"🗓 <b>Expiry:</b> {fmt_expiry(usr.get('expiry'))}",
        f"",
        f"🌐 <b>Server Stats</b>",
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈",
    ]
    if sys_info.get("cpu"):
        lines.append(f"⚙️ <b>CPU:</b> <code>{sys_info['cpu']}</code>")
    if sys_info.get("ram_used"):
        lines.append(f"💾 <b>RAM:</b> <code>{sys_info['ram_used']} / {sys_info['ram_total']} ({sys_info['ram_pct']})</code>")
    if sys_info.get("disk_used"):
        lines.append(f"💿 <b>Disk:</b> <code>{sys_info['disk_used']} / {sys_info['disk_total']}</code>")
    if sys_info.get("bot_ram"):
        lines.append(f"🤖 <b>Bot RAM:</b> <code>{sys_info['bot_ram']}</code>")
    uptime = fmt_duration((_now_ist() - START_TIME).total_seconds())
    lines.append(f"⏱️ <b>Bot Uptime:</b> <code>{h(uptime)}</code>")

    if running:
        lines.append(f"")
        lines.append(f"<b>Running Bot Details:</b>")
        for b in running[:5]:
            proc_info = get_bot_proc_info(b["bot_id"])
            bot_line = f"• <code>{h(b['file_name'])}</code> — {h(bot_uptime(b))}"
            if proc_info.get("ram"):
                bot_line += f" | RAM: {proc_info['ram']}"
            if proc_info.get("cpu"):
                bot_line += f" | CPU: {proc_info['cpu']}"
            lines.append(bot_line)

    await q.edit_message_text(
        "\n".join(lines),
        reply_markup=kb_back("home"),
        parse_mode=ParseMode.HTML,
    )

#  PIP INSTALL

def kb_pip_management() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📦 Install Pip",   callback_data="pip_install", style="primary")],
        [InlineKeyboardButton("🗑️ Uninstall Pip", callback_data="pip_uninstall", style="primary")],
        [InlineKeyboardButton("🏠 Home",          callback_data="home", style="primary")],
    ])

async def cb_pip_management(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    clr_st(ctx)  # clear any pending pip state when returning to menu
    await q.edit_message_text(
        "⚙️ <b>Pip Management</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "Choose an action below:",
        reply_markup=kb_pip_management(),
        parse_mode=ParseMode.HTML,
    )

async def cb_pip_install(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "pip_install")
    await q.edit_message_text(
        "📦 <b>Install Pip Package</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "📝 <b>Send the package name(s) to install.</b>\n\n"
        "<b>Accepted formats:</b>\n"
        "  • <code>requests</code>\n"
        "  • <code>pip install requests</code>\n"
        "  • <code>pyrogram tgcrypto</code>\n"
        "  • <code>python-dotenv==1.0.1</code>\n\n"
        "<b>⚠️ Only install packages you trust.</b>",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="pip_management", style="primary"),
             InlineKeyboardButton("🏠 Home", callback_data="home", style="primary")],
        ]),
        parse_mode=ParseMode.HTML,
    )

async def cb_pip_error(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid = update.effective_user.id
    err = PIP_ERRORS.get(uid)
    if not err:
        await q.edit_message_text("ℹ️ No pip error details found.", reply_markup=kb_pip_management(), parse_mode=ParseMode.HTML)
        return
    raw = err.get("error","")
    if len(raw) > 3000:
        raw = raw[:3000] + "\n…(truncated)"
    await q.edit_message_text(
        f"❌ <b>Pip Error Details</b>\n\n<code>{h(raw)}</code>",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="pip_management", style="primary"),
             InlineKeyboardButton("🏠 Home", callback_data="home", style="primary")],
        ]),
        parse_mode=ParseMode.HTML,
    )

async def cb_pip_uninstall(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "pip_uninstall")
    await q.edit_message_text(
        "🗑️ <b>Uninstall Pip Package</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "📝 <b>Send the package name(s) to uninstall.</b>\n\n"
        "<b>Accepted formats:</b>\n"
        "  • <code>requests</code>\n"
        "  • <code>pyrogram tgcrypto</code>\n"
        "  • <code>python-dotenv</code>\n\n"
        "<b>⚠️ Only uninstall packages you no longer need.</b>",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 Back", callback_data="pip_management", style="primary"),
             InlineKeyboardButton("🏠 Home", callback_data="home", style="primary")],
        ]),
        parse_mode=ParseMode.HTML,
    )


#  UPLOAD

async def cb_upload(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid = update.effective_user.id
    # Rate limit: max 3 upload attempts per 60 seconds
    if check_rate_limit(uid, "upload", max_calls=3, window=60):
        await q.answer("⏳ Slow down! Wait a moment before uploading again.", show_alert=True)
        return
    check_expiry(uid)
    unlimited = is_unlimited(uid)
    lim  = get_file_limit(uid)
    used = bot_count(uid)
    if not unlimited and used >= lim:
        usr = get_user(uid)
        plan_key = usr.get("plan","free") if usr else "free"
        if plan_key not in PLANS:
            plan_key = "free"
        plan_name = PLANS[plan_key]["name"]
        await q.edit_message_text(
            f"❌ <b>File Limit Reached!</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"Your <b>{plan_name}</b> plan allows <b>{lim}</b> file(s).\n"
            f"You're at <b>{used}/{lim}</b>.\n\n"
            f"<b>Upgrade your plan to host more bots.</b>",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("💰 Upgrade Plan", callback_data="plans", style="primary")],
                [InlineKeyboardButton("🏠 Home",         callback_data="home", style="primary")],
            ]), parse_mode=ParseMode.HTML,
        )
        return
    set_st(ctx, "upload")
    storage_info = "♾️ Unlimited storage" if unlimited else f"{used}/{lim} files used"
    await q.edit_message_text(
        f"➕ <b>Upload Bot</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"📤 <b>Send your bot file now.</b>\n\n"
        f"<b>Supported formats:</b>\n"
        f"  ✅ <code>.py</code>  — Python bot\n\n"
        f"📊 <b>Storage:</b> <b>{storage_info}</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="home", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )

#  MY BOTS

async def cb_mybots(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    sync_statuses()
    uid  = update.effective_user.id
    bots = user_bots(uid)
    if not bots:
        await q.edit_message_text(
            "🤖 <b>My Bots</b>\n"
            "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            "📭 <b>You haven't uploaded any bots yet.\n"
            "Tap ➕ Upload Bot to get started!</b>",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("➕ Upload Bot", callback_data="upload", style="success")],
                [InlineKeyboardButton("🏠 Home",       callback_data="home", style="primary")],
            ]), parse_mode=ParseMode.HTML,
        )
        return
    rows = []
    for b in bots:
        if b.get("pending"):
            label = f"⏳ {b['file_name']} [Pending]"
        else:
            ls = _live_status(b)
            status_icon = "🟢" if ls=="running" else ("🟡" if ls=="error" else "🔴")  # manually_stopped also gets 🔴
            label = f"{status_icon} {b['file_name']}"
        rows.append([InlineKeyboardButton(label, callback_data=f"bot_{b['bot_id']}", style="primary")])
    rows.append([InlineKeyboardButton("🏠 Home", callback_data="home", style="primary")])
    run = sum(1 for b in bots if _live_status(b) == "running")
    await q.edit_message_text(
        f"🤖 <b>My Bots</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"📁 <b>Total:</b> <b>{len(bots)}</b>  •  🟢 <b>Running:</b> <b>{run}</b>\n\n"
        f"<b>Select a bot to manage:</b>",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )

async def cb_bot_detail(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    bid = q.data.split("bot_",1)[1]
    sync_statuses()
    b   = get_bot(bid)
    if not b or int(b["user_id"]) != int(update.effective_user.id):
        await q.answer("❌ Bot not found.", show_alert=True)
        return
    await q.answer()
    await _show_bot(q, b, bid)

def _live_status(b: dict) -> str:
    """Status as it should be shown right now: if the stored status says
    'running' but the pid is actually dead/zombie, report it as stopped
    instead of trusting the (possibly stale) stored value. Belt-and-braces
    on top of sync_statuses() for any render path that doesn't call it."""
    s = b.get("status", "stopped")
    pid = b.get("pid")
    if s == "running" and (not pid or not _alive(pid)):
        return "stopped"
    return s

async def _show_bot(q, b: dict, bid: str, back: str = "mybots"):
    s   = _live_status(b)
    pid = b.get("pid")
    pending = b.get("pending", False)
    if pending:
        text = (
            f"🤖 <b>Bot Details</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📄 <b>File:</b>   <code>{h(b['file_name'])}</code>\n"
            f"🆔 <b>ID:</b>     <code>{bid}</code>\n"
            f"📊 <b>Status:</b> ⏳ <b>Pending Approval</b>\n\n"
            f"<b>Waiting for owner approval.\nYou'll be notified once approved.</b>"
        )
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("🗑️ Delete", callback_data=f"bact_delete_{bid}", style="danger"),
             InlineKeyboardButton("🔙 Back",   callback_data=back, style="primary")],
        ])
    else:
        proj  = b.get("project_name","").strip()
        ipid  = b.get("internal_pid")
        bot_username = await auto_fetch_bot_username(
            get_decrypted_bot_token(b) or extract_bot_token(b.get("file_path",""))
        )
        username_line = f"👤 <b>Username:</b> @{h(bot_username)}\n" if bot_username else ""
        text = (
            f"🤖 <b>Bot Details</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            + (f"🔢 <b>Bot #:</b>   <code>{ipid}</code>\n" if ipid else "")
            + f"📄 <b>File:</b>   <code>{h(b['file_name'])}</code>\n"
            + (f"📁 <b>Project:</b> <code>{h(proj)}</code>\n" if proj else "")
            + f"🆔 <b>ID:</b>     <code>{bid}</code>\n"
            + username_line
            + f"📊 <b>Status:</b> {si(s)}\n"
        )
        if pid and s == "running" and _alive(pid):
            text += f"⏱️ <b>Uptime:</b> <code>{h(bot_uptime(b))}</code>\n"
            proc_info = get_bot_proc_info(bid)
            if proc_info.get("ram"):
                text += f"💾 <b>RAM:</b>    <code>{proc_info['ram']}</code>\n"
            if proc_info.get("cpu"):
                text += f"🖥️ <b>CPU:</b>    <code>{proc_info['cpu']}</code>\n"
        text += "\n<b>Use the buttons below to manage.</b>"
        kb = kb_bot(bid, s, back)
    try:
        await q.edit_message_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)
    except Exception as e:
        # Don't let a failed edit swallow the final status silently — make
        # sure the user always finds out whether their bot is running.
        log.warning("_show_bot: edit failed, sending fresh message instead: %s", e)
        try:
            await q.get_bot().send_message(
                chat_id=q.message.chat_id if q.message else q.from_user.id,
                text=text, reply_markup=kb, parse_mode=ParseMode.HTML,
            )
        except Exception as e2:
            log.warning("_show_bot: fallback send_message also failed: %s", e2)

async def cb_bot_action(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    parts = q.data.split("_", 2)
    if len(parts) < 3:
        await q.answer()
        return
    action, bid = parts[1], parts[2]
    b = get_bot(bid)
    if not b or int(b["user_id"]) != int(update.effective_user.id):
        await q.answer("⛔ Not your bot.", show_alert=True)
        return
    await q.answer()
    uid = update.effective_user.id

    if action == "replace":
        set_st(ctx, "user_replace_file_upload", replace_bid=bid)
        await q.edit_message_text(
            f"🔁 <b>Replace Bot File</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📄 <b>Current:</b> <code>{h(b['file_name'])}</code>\n\n"
            f"<b>Send the new file now.</b>\n"
            f"<b>The bot will be stopped, file replaced, then restarted automatically.</b>",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data=f"bot_{bid}", style="danger")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if action == "transfer":
        set_st(ctx, "user_transfer_bot", transfer_bid=bid)
        await q.edit_message_text(
            f"👤 <b>Transfer Bot Ownership</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📄 <b>Bot:</b> <code>{h(b['file_name'])}</code>\n\n"
            f"<b>Send the User ID of the new owner.</b>\n"
            f"<b>The new user must already be registered in this bot.</b>",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data=f"bot_{bid}", style="danger")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if action == "logs":
        logs_md = format_logs_md2(bid)
        await q.edit_message_text(
            logs_md,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄 Refresh",    callback_data=f"bact_logs_{bid}", style="primary"),
                 InlineKeyboardButton("📡 Live Logs", callback_data=f"bact_livelogs_{bid}", style="primary")],
                [InlineKeyboardButton("🔙 Back",       callback_data=f"bot_{bid}", style="primary")],
            ]),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return

    if action == "save":
        send_fp = get_sendable_file_path(b)
        if not send_fp:
            await q.answer("❌ File not found.", show_alert=True)
            return
        stored_fp = b.get("file_path","")
        _tmp_created = (send_fp != stored_fp and os.path.exists(send_fp))
        try:
            with open(send_fp,"rb") as f:
                await ctx.bot.send_document(
                    chat_id=uid, document=f, filename=b["file_name"],
                    caption=f"💾 <b>Your Bot File</b>\n📄 <code>{h(b['file_name'])}</code>",
                    parse_mode=ParseMode.HTML,
                )
            await q.answer("✅ File sent to your DM!", show_alert=True)
        except Exception as e:
            await q.answer(f"❌ {e}", show_alert=True)
        finally:
            if _tmp_created and os.path.exists(send_fp):
                try:
                    os.remove(send_fp)
                except Exception:
                    pass
        return

    if action == "start":
        if b.get("pending"):
            await q.answer("⏳ Awaiting owner approval.", show_alert=True)
            return
        run_lim = get_run_limit(uid)
        if running_bot_count(uid) >= run_lim:
            await q.edit_message_text(
                f"⚠️ <b>Running Limit Reached!</b>\n"
                f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"Your plan allows <b>{run_lim}</b> running bot(s) at a time.\n\n"
                f"<b>Stop a running bot first, or upgrade your plan.</b>",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("💰 Upgrade", callback_data="plans", style="primary")],
                    [InlineKeyboardButton("🤖 My Bots", callback_data="mybots", style="primary")],
                ]), parse_mode=ParseMode.HTML,
            )
            return
        await q.edit_message_text(
            f"🚀 <b>Starting your bot…</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📄 <code>{h(b['file_name'])}</code>\n"
            f"⏳ <b>Installing dependencies — please wait</b>",
            parse_mode=ParseMode.HTML,
        )
        ok, msg = await asyncio.get_running_loop().run_in_executor(None, proc_start, bid)
    elif action == "stop":
        ok, msg = proc_stop(bid)
    elif action == "restart":
        await q.edit_message_text(
            f"⚙️ <b>Installing modules &amp; restarting your bot…</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📄 <code>{h(b['file_name'])}</code>\n\n"
            f"⏳ <b>This may take a while, please wait…</b>",
            parse_mode=ParseMode.HTML,
        )
        ok, msg = await asyncio.get_running_loop().run_in_executor(None, proc_restart, bid)
    elif action == "delete":
        proc_stop(bid)
        remove_bot_file(b)
        del_bot(bid)
        await q.edit_message_text(
            f"🗑️ <b>Bot Deleted</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"<code>{h(b['file_name'])}</code> has been removed.",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🤖 My Bots", callback_data="mybots", style="primary"),
                 InlineKeyboardButton("🏠 Home",    callback_data="home", style="primary")],
            ]), parse_mode=ParseMode.HTML,
        )
        return
    else:
        return
    if action in ("start","restart") and not ok:
        fail_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("📋 Logs", callback_data=f"bact_logs_{bid}", style="primary")],
            [InlineKeyboardButton("🔙 Back", callback_data=f"bot_{bid}", style="primary")],
        ])
        await _deliver_result(q, ctx, msg, fail_kb)
        return
    b2 = get_bot(bid)
    if b2:
        await _show_bot(q, b2, bid)
    else:
        await _deliver_result(q, ctx, msg, None)


async def _deliver_result(q, ctx: ContextTypes.DEFAULT_TYPE, text: str, kb: Optional[InlineKeyboardMarkup]):
    """
    Guarantees the user actually sees the final result (bot started / failed /
    etc.) instead of getting stuck on "Installing modules…" forever.

    Long-running actions like proc_start can take a while (module scan +
    pip install), and by the time we try to edit the original message that
    edit can fail (message deleted, edited elsewhere, etc.). Previously such
    a failure was swallowed by the global error handler and the user never
    found out what happened. Now we fall back to sending a brand-new message
    with the same result so nothing is ever silently lost.
    """
    try:
        await q.edit_message_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)
    except Exception as e:
        log.warning("Falling back to send_message after edit failure: %s", e)
        try:
            await ctx.bot.send_message(
                chat_id=q.message.chat_id if q.message else q.from_user.id,
                text=text, reply_markup=kb, parse_mode=ParseMode.HTML,
            )
        except Exception as e2:
            log.warning("Fallback send_message also failed: %s", e2)

#  ADMIN — /admin_panel

async def cmd_admin(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("🚫 <b>Aᴅᴍɪɴꜱ Oɴʟʏ.</b>", parse_mode=ParseMode.HTML)
        return
    clr_st(ctx)
    await update.message.reply_text(
        "👑 <b>Admin Panel</b> 💎\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>@{DEVELOPER_USERNAME} — UnknownXHosting New Era</b>",
        reply_markup=kb_admin(), parse_mode=ParseMode.HTML,
    )

async def cmd_logs(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("🚫 <b>Aᴅᴍɪɴꜱ Oɴʟʏ.</b>", parse_mode=ParseMode.HTML)
        return
    users = all_users()
    if not users:
        await update.message.reply_text("👥 <b>No users registered yet.</b>", parse_mode=ParseMode.HTML)
        return
    lines = [
        "UnknownXHosting New Era — User Logs",
        f"Generated: {_now_ist():%Y-%m-%d %H:%M:%S} IST",
        f"Total Users: {len(users)}",
        "=" * 50, "",
    ]
    bans_set = {str(b) for b in _load().get("bans", [])}
    for i, (uid_s, u) in enumerate(users.items(), 1):
        ban_status = "Banned 🚫" if uid_s in bans_set else "Active ✅"
        plan_val = u.get("plan", "free")
        expiry_val = u.get("expiry") or "N/A"
        lines += [
            f"#{i}",
            f"  Name       : {u.get('first_name', 'N/A')}",
            f"  Username   : {'@'+u['username'] if u.get('username') else 'N/A'}",
            f"  User ID    : {uid_s}",
            f"  Plan       : {plan_val}",
            f"  Ban Status : {ban_status}",
            "",
        ]
    txt = "\n".join(lines)
    log_path = os.path.join(BASE_DIR, "users_log.txt")
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(txt)
    with open(log_path, "rb") as f:
        await update.message.reply_document(
            document=f,
            filename=f"users_{_now_ist():%Y%m%d_%H%M%S}.txt",
            caption=(
                f"📋 <b>User Logs</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"👥 <b>Total:</b> <b>{len(users)}</b> users\n"
                f"<b>{_now_ist():%d %b %Y %H:%M} IST</b>"
            ),
            parse_mode=ParseMode.HTML,
        )
    try:
        os.remove(log_path)
    except Exception:
        pass

async def cmd_restore_backup(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """
    /restore_backup — Owner-only command to manually restore users from a backup file.

    Usage:
      1. Reply to a backup .txt file in Telegram with /restore_backup
         OR
      2. Send /restore_backup and then send the .txt file in the next message

    The command accepts any backup file that was previously uploaded by the bot
    (tagged #BOT_STORAGE_BACKUP or #BOT_STORAGE). It merges the user list and
    plans from the file into the current database — existing users keep their
    current plan if it is better (higher tier) than what is in the backup.
    """
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("🚫 <b>Aᴅᴍɪɴꜱ Oɴʟʏ.</b>", parse_mode=ParseMode.HTML)
        return

    # Check if owner replied to a document message
    replied = update.message.reply_to_message
    doc = None
    if replied:
        doc = getattr(replied, "document", None)

    # Also check if the command message itself has a document (forwarded with caption)
    if not doc:
        doc = getattr(update.message, "document", None)

    if not doc:
        # Ask owner to send/forward the backup file
        set_st(ctx, "awaiting_restore_backup_file")
        await update.message.reply_text(
            "📥 <b>Manual Backup Restore</b>\n"
            "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            "Send or forward the backup <code>.txt</code> file from your backup channel.\n\n"
            "<b>The file must be a JSON backup generated by this bot "
            "(tagged #BOT_STORAGE_BACKUP or #BOT_STORAGE).</b>\n\n"
            "Send /cancel to abort.",
            parse_mode=ParseMode.HTML,
        )
        return

    await _do_restore_from_doc(update, ctx, doc)


async def _do_restore_from_doc(update: Update, ctx: ContextTypes.DEFAULT_TYPE, doc):
    status_msg = await update.message.reply_text(
        "⏳ <b>Downloading backup file…</b>",
        parse_mode=ParseMode.HTML,
    )
    tmp_path = os.path.join(BASE_DIR, f".restore_dl_{uuid.uuid4().hex}.txt")
    try:
        tg_file = await ctx.bot.get_file(doc.file_id)
        await tg_file.download_to_drive(tmp_path)
        with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except Exception as e:
        await status_msg.edit_text(
            f"❌ <b>Failed to download file:</b> <code>{h(str(e))}</code>",
            parse_mode=ParseMode.HTML,
        )
        return
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass

    await status_msg.edit_text("⏳ <b>Parsing backup data…</b>", parse_mode=ParseMode.HTML)

    restored = _cloud_deserialise(raw)
    if not restored or "users" not in restored:
        await status_msg.edit_text(
            "❌ <b>Invalid backup file.</b>\n\n"
            "<b>Make sure the file is a JSON backup generated by this bot.</b>",
            parse_mode=ParseMode.HTML,
        )
        return

    backup_users: dict = restored.get("users", {})
    backup_bans: list  = restored.get("bans", [])

    if not backup_users:
        await status_msg.edit_text(
            "⚠️ <b>Backup file has no users.</b>",
            parse_mode=ParseMode.HTML,
        )
        return

    # Plan tier order — higher index = better plan
    _PLAN_TIER = ["free", "baby", "basic", "premium", "god", "ultimate", "lifetime"]

    def _plan_rank(plan: str) -> int:
        try:
            return _PLAN_TIER.index(plan)
        except ValueError:
            return 0

    await status_msg.edit_text("⏳ <b>Merging users into database…</b>", parse_mode=ParseMode.HTML)

    added   = 0
    updated = 0
    skipped = 0

    d = _load()
    for uid_s, bu in backup_users.items():
        if not uid_s or not isinstance(bu, dict):
            continue
        uid_int = bu.get("user_id") or int(uid_s)
        existing = d["users"].get(uid_s)

        if existing is None:
            # New user — add them with their backed-up plan
            d["users"][uid_s] = {
                "user_id":           uid_int,
                "username":          bu.get("username", ""),
                "first_name":        bu.get("first_name", ""),
                "plan":              bu.get("plan", "free"),
                "expiry":            bu.get("expiry"),
                "bots":              [],   # bots are server-specific
                "approval_override": bu.get("approval_override"),
            }
            added += 1
        else:
            # Existing user — update name/username, keep the BETTER plan
            changed = False
            for field in ("username", "first_name"):
                v = bu.get(field, "")
                if v and existing.get(field) != v:
                    existing[field] = v
                    changed = True
            # Upgrade plan if backup has a better tier
            cur_rank  = _plan_rank(existing.get("plan", "free"))
            back_rank = _plan_rank(bu.get("plan", "free"))
            if back_rank > cur_rank:
                existing["plan"]   = bu.get("plan", "free")
                existing["expiry"] = bu.get("expiry")
                changed = True
            if changed:
                updated += 1
            else:
                skipped += 1

    # Merge bans (add any new ones, don't remove existing)
    existing_bans = {str(b) for b in d.get("bans", [])}
    for b in backup_bans:
        if str(b) not in existing_bans:
            d["bans"].append(str(b))

    _save(d)
    clr_st(ctx)

    await status_msg.edit_text(
        f"✅ <b>Backup Restored Successfully!</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"📥 <b>Backup had:</b> <b>{len(backup_users)}</b> users\n\n"
        f"🆕 <b>New users added:</b> <b>{added}</b>\n"
        f"🔄 <b>Users updated (plan/name):</b> <b>{updated}</b>\n"
        f"⏭ <b>Users unchanged:</b> <b>{skipped}</b>\n\n"
        f"<b>Plans are kept at the highest tier between backup and current data.</b>",
        parse_mode=ParseMode.HTML,
    )


async def cmd_fetch_backup(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """
    /fetch_backup — Owner-only.
    Scans the private storage channel for the most recent backup or storage
    .txt file, downloads it, and merges all users + plans into the live DB.
    Works exactly like the startup auto-restore but can be triggered anytime
    without restarting the bot — useful after hosting migration.
    """
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("🚫 <b>Aᴅᴍɪɴꜱ Oɴʟʏ.</b>", parse_mode=ParseMode.HTML)
        return

    pm = await update.message.reply_text(
        "🔍 <b>Scanning backup channel…</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "<b>Looking for storage/backup files in the channel. This may take a few seconds…</b>",
        parse_mode=ParseMode.HTML,
    )

    payload_str: Optional[str] = None
    source_tag  = ""

    async def _dl(file_id: str) -> Optional[str]:
        tmp = os.path.join(BASE_DIR, f".fb_dl_{uuid.uuid4().hex}.txt")
        try:
            tg_file = await ctx.bot.get_file(file_id)
            await tg_file.download_to_drive(tmp)
            with open(tmp, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            return None
        finally:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass

    both_tags = (CLOUD_STORAGE_TAG, CLOUD_BACKUP_TAG)

    try:
        chat = await ctx.bot.get_chat(CLOUD_STORAGE_CHAT_ID)
        pinned = getattr(chat, "pinned_message", None)
        if pinned:
            caption = (pinned.caption or "").strip()
            doc = getattr(pinned, "document", None)
            if doc and any(tag in caption for tag in both_tags):
                content = await _dl(doc.file_id)
                if content:
                    payload_str = content
                    source_tag  = CLOUD_BACKUP_TAG if CLOUD_BACKUP_TAG in caption else CLOUD_STORAGE_TAG
                    await pm.edit_text(
                        "📌 <b>Found pinned storage file — downloading…</b>",
                        parse_mode=ParseMode.HTML,
                    )
    except Exception:
        pass

    if not payload_str:
        await pm.edit_text(
            "🔍 <b>Checking recent channel posts…</b>",
            parse_mode=ParseMode.HTML,
        )
        try:
            url = f"https://api.telegram.org/bot{Bot_token}/getUpdates?limit=100&timeout=0"
            req = _urlreq.Request(url)
            with _urlreq.urlopen(req, timeout=20) as r:
                result = json.loads(r.read().decode())
            if result.get("ok"):
                for upd in reversed(result.get("result", [])):
                    msg = upd.get("channel_post") or upd.get("message")
                    if not msg:
                        continue
                    if str(msg.get("chat", {}).get("id", "")) != str(CLOUD_STORAGE_CHAT_ID):
                        continue
                    caption = (msg.get("caption") or "").strip()
                    doc = msg.get("document")
                    if doc and any(tag in caption for tag in both_tags):
                        content = await _dl(doc["file_id"])
                        if content:
                            payload_str = content
                            source_tag  = CLOUD_BACKUP_TAG if CLOUD_BACKUP_TAG in caption else CLOUD_STORAGE_TAG
                            break
        except Exception:
            pass

    if not payload_str:
        await pm.edit_text(
            "🔍 <b>Scanning channel message history…</b>\n"
            "<b>Probing recent message IDs for backup files…</b>",
            parse_mode=ParseMode.HTML,
        )
        try:
            chat_id = CLOUD_STORAGE_CHAT_ID
            start_id = 500
            try:
                ch_info = await ctx.bot.get_chat(chat_id)
                p2 = getattr(ch_info, "pinned_message", None)
                if p2 and p2.message_id:
                    start_id = p2.message_id + 50
            except Exception:
                pass

            for mid in range(start_id, max(start_id - 400, 0), -1):
                try:
                    params = _urlparse.urlencode({
                        "chat_id":             chat_id,
                        "from_chat_id":        chat_id,
                        "message_id":          mid,
                        "disable_notification": "true",
                    })
                    fwd_url = f"https://api.telegram.org/bot{Bot_token}/forwardMessage?{params}"
                    with _urlreq.urlopen(_urlreq.Request(fwd_url), timeout=6) as r:
                        res = json.loads(r.read().decode())
                    if not res.get("ok"):
                        continue
                    fwd_msg = res.get("result", {})
                    caption = (fwd_msg.get("caption") or "").strip()
                    doc     = fwd_msg.get("document")
                    # Delete forwarded copy immediately — keep channel clean
                    fwd_mid = fwd_msg.get("message_id")
                    if fwd_mid:
                        try:
                            dp = _urlparse.urlencode({"chat_id": chat_id, "message_id": fwd_mid})
                            with _urlreq.urlopen(_urlreq.Request(
                                f"https://api.telegram.org/bot{Bot_token}/deleteMessage?{dp}"
                            ), timeout=5):
                                pass
                        except Exception:
                            pass
                    if doc and any(tag in caption for tag in both_tags):
                        content = await _dl(doc["file_id"])
                        if content:
                            payload_str = content
                            source_tag  = CLOUD_BACKUP_TAG if CLOUD_BACKUP_TAG in caption else CLOUD_STORAGE_TAG
                            break
                except Exception:
                    continue
        except Exception:
            pass

    if not payload_str:
        await pm.edit_text(
            "❌ <b>No backup file found in the channel.</b>\n\n"
            "<b>Make sure:\n"
            "• The bot is admin in the storage channel\n"
            "• At least one backup has been saved (tagged #BOT_STORAGE or #BOT_STORAGE_BACKUP)\n"
            "• CLOUD_STORAGE_CHAT_ID is set correctly</b>",
            parse_mode=ParseMode.HTML,
        )
        return

    await pm.edit_text("⏳ <b>Parsing and merging user data…</b>", parse_mode=ParseMode.HTML)

    restored = _cloud_deserialise(payload_str)
    if not restored or "users" not in restored:
        await pm.edit_text(
            "❌ <b>Failed to parse backup file.</b>\n"
            "<b>The file doesn't appear to be a valid bot storage JSON.</b>",
            parse_mode=ParseMode.HTML,
        )
        return

    backup_users: dict = restored.get("users", {})
    backup_bans:  list = restored.get("bans",  [])
    backup_codes: dict = restored.get("codes", {})

    _PLAN_TIER = ["free", "baby", "basic", "premium", "god", "ultimate", "lifetime"]
    def _rank(plan: str) -> int:
        try:    return _PLAN_TIER.index(plan)
        except: return 0

    added = updated = skipped = 0
    d = _load()

    for uid_s, bu in backup_users.items():
        if not uid_s or not isinstance(bu, dict):
            continue
        try:
            uid_int = bu.get("user_id") or int(uid_s)
        except Exception:
            continue
        existing = d["users"].get(uid_s)
        if existing is None:
            d["users"][uid_s] = {
                "user_id":           uid_int,
                "username":          bu.get("username", ""),
                "first_name":        bu.get("first_name", ""),
                "plan":              bu.get("plan", "free"),
                "expiry":            bu.get("expiry"),
                "bots":              [],
                "approval_override": bu.get("approval_override"),
            }
            added += 1
        else:
            changed = False
            for field in ("username", "first_name"):
                v = bu.get(field, "")
                if v and existing.get(field) != v:
                    existing[field] = v
                    changed = True
            if _rank(bu.get("plan", "free")) > _rank(existing.get("plan", "free")):
                existing["plan"]   = bu.get("plan", "free")
                existing["expiry"] = bu.get("expiry")
                changed = True
            if changed:
                updated += 1
            else:
                skipped += 1

    # Merge bans
    existing_bans = {str(b) for b in d.get("bans", [])}
    new_bans = 0
    for b in backup_bans:
        if str(b) not in existing_bans:
            d["bans"].append(str(b))
            new_bans += 1

    # Merge codes (don't overwrite existing ones)
    for code, cdata in backup_codes.items():
        if code not in d.get("codes", {}):
            d.setdefault("codes", {})[code] = cdata

    _save(d)

    file_label = "Backup" if source_tag == CLOUD_BACKUP_TAG else "Storage"
    await pm.edit_text(
        f"✅ <b>Channel {file_label} Fetched &amp; Merged!</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"📦 <b>File tag:</b> <code>{h(source_tag)}</code>\n"
        f"👥 <b>Users in file:</b> <b>{len(backup_users)}</b>\n\n"
        f"🆕 <b>New users added:</b> <b>{added}</b>\n"
        f"🔄 <b>Updated (plan/name):</b> <b>{updated}</b>\n"
        f"⏭  <b>Already up to date:</b> <b>{skipped}</b>\n"
        f"🚫 <b>New bans imported:</b> <b>{new_bans}</b>\n\n"
        f"<b>Plans kept at the highest tier between backup and live data.</b>",
        parse_mode=ParseMode.HTML,
    )


#  ADMIN — Generate Backup / Upload Backup (zip, per-owner folders)

def kb_confirm_gen_backup() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Yes, Backup",  callback_data="adm_gen_backup_yes", style="success"),
         InlineKeyboardButton("❌ No, Cancel",   callback_data="adm_gen_backup_no",  style="danger")],
    ])


async def cb_adm_gen_backup(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id != OWNER_ID:
        await q.answer("Unauthorized.", show_alert=True)
        return
    await q.edit_message_text(
        "📦 <b>Generate Backup</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "⚠️ <b>Are you sure</b> you want to perform a full backup?\n\n"
        "<b>Every hosted bot's uploaded source, its LIVE runtime data "
        "(databases, sessions, JSON/SQLite state), its end-user list, and "
        "owner details will all be zipped in separate per-owner folders and "
        "sent to you right here — so a restart or restore leaves no bot "
        "data behind.</b>",
        reply_markup=kb_confirm_gen_backup(), parse_mode=ParseMode.HTML,
    )


async def cb_adm_gen_backup_no(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id != OWNER_ID:
        await q.answer("Unauthorized.", show_alert=True)
        return
    await q.edit_message_text(
        "🚫 <b>Backup Cancelled</b>",
        reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
    )


async def cb_adm_gen_backup_yes(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id != OWNER_ID:
        await q.answer("Unauthorized.", show_alert=True)
        return

    await q.edit_message_text(
        "⏳ <b>Packing bot files, data &amp; owner details…</b>\n"
        "<b>Please wait, this may take a moment.</b>",
        parse_mode=ParseMode.HTML,
    )

    zip_path = None
    try:
        zip_path, stats = await asyncio.to_thread(_create_full_backup_zip_sync)
        size_mb = stats["size"] / (1024 * 1024)

        if stats["size"] > MAX_BYTES:
            await q.edit_message_text(
                "⚠️ <b>Backup too large to send via Telegram</b>\n"
                "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"📦 <b>Size:</b> <b>{size_mb:.1f} MB</b>\n\n"
                f"<b>Saved locally at:</b> <code>{h(zip_path)}</code>",
                reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
            )
            return

        with open(zip_path, "rb") as f:
            await ctx.bot.send_document(
                chat_id=update.effective_chat.id,
                document=f,
                filename=os.path.basename(zip_path),
                caption=(
                    "✅ <b>Backup Generated!</b> 📦\n"
                    "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"👥 <b>Owners:</b> <b>{stats['owners']}</b>\n"
                    f"🤖 <b>Bots:</b> <b>{stats['bots']}</b>\n"
                    f"🗂️ <b>Files:</b> <b>{stats['files']}</b>\n"
                    f"💽 <b>Size:</b> <b>{size_mb:.2f} MB</b>\n\n"
                    "<b>Keep this file safe — use \"Upload Backup\" to restore it.</b>"
                ),
                parse_mode=ParseMode.HTML,
            )
    except Exception as e:
        log.warning("Generate backup failed: %s", e)
        try:
            await q.edit_message_text(
                f"❌ <b>Backup failed:</b> <code>{h(str(e))}</code>",
                reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
    finally:
        if zip_path and os.path.exists(zip_path):
            try:
                os.remove(zip_path)
            except Exception:
                pass


async def cb_adm_upload_backup(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id != OWNER_ID:
        await q.answer("Unauthorized.", show_alert=True)
        return
    set_st(ctx, "adm_upload_backup_file")
    await q.edit_message_text(
        "📤 <b>Upload Backup</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "📩 Send or forward the backup <b>.zip</b> file generated by this bot.\n\n"
        "<b>Bots will be reassigned back to their original owners automatically, "
        "along with every data file (databases, sessions, state, etc.) — nothing "
        "is lost.</b>",
        reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
    )


async def _do_upload_backup_restore(update: Update, ctx: ContextTypes.DEFAULT_TYPE, doc):
    clr_st(ctx)
    fname = (doc.file_name or "").lower()
    if not fname.endswith(".zip"):
        await update.message.reply_text(
            "❌ <b>Please send a valid backup <code>.zip</code> file.</b>",
            reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
        )
        return

    status_msg = await update.message.reply_text(
        "⏳ <b>Processing…</b>\n<b>Downloading &amp; restoring backup file.</b>",
        parse_mode=ParseMode.HTML,
    )

    tmp_zip = os.path.join(BASE_DIR, f".upload_backup_{uuid.uuid4().hex}.zip")
    try:
        tg_file = await ctx.bot.get_file(doc.file_id)
        await tg_file.download_to_drive(tmp_zip)
    except Exception as e:
        await status_msg.edit_text(
            f"❌ <b>Failed to download backup:</b> <code>{h(str(e))}</code>",
            reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
        )
        return

    try:
        await status_msg.edit_text(
            "⏳ <b>Processing…</b>\n<b>Restoring bot files to their owners.</b>",
            parse_mode=ParseMode.HTML,
        )
        stats = await asyncio.to_thread(_restore_full_backup_zip_sync, tmp_zip)
        err_line = f"\n⚠️ <b>Errors:</b> <b>{stats['errors']}</b>" if stats.get("errors") else ""
        await status_msg.edit_text(
            "✅ <b>Backup Restored!</b> 📦\n"
            "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"👥 <b>Owners restored:</b> <b>{stats['owners']}</b>\n"
            f"🤖 <b>Bots re-linked:</b> <b>{stats['bots']}</b>\n"
            f"🗂️ <b>Files restored:</b> <b>{stats['files']}</b>"
            f"{err_line}\n\n"
            "<b>All bot files have been assigned back to their owner IDs.</b>",
            reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
        )
    except zipfile.BadZipFile:
        await status_msg.edit_text(
            "❌ <b>Invalid backup file.</b>\n<b>Not a valid .zip archive.</b>",
            reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
        )
    except Exception as e:
        log.warning("Upload backup restore failed: %s", e)
        await status_msg.edit_text(
            f"❌ <b>Restore failed:</b> <code>{h(str(e))}</code>",
            reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
        )
    finally:
        try:
            if os.path.exists(tmp_zip):
                os.remove(tmp_zip)
        except Exception:
            pass


async def cb_adm_panel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    clr_st(ctx)
    panel_text = (
        "👑 <b>Admin Panel</b> ✨\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>@{DEVELOPER_USERNAME} — UnknownXHosting New Era</b>"
    )
    is_media_msg = bool(q.message and q.message.document)
    if is_media_msg:
        # This message is a document with a caption (e.g. an approval/rejection
        # notice) — it has no text body, so edit_message_text always fails on
        # it. Send the panel as a fresh message instead of trying to edit it.
        try:
            await ctx.bot.send_message(
                chat_id=update.effective_chat.id,
                text=panel_text,
                reply_markup=kb_admin(), parse_mode=ParseMode.HTML,
            )
        except Exception as e:
            log.warning("Could not send admin panel after media message: %s", e)
        return
    try:
        await q.edit_message_text(
            panel_text,
            reply_markup=kb_admin(), parse_mode=ParseMode.HTML,
        )
    except Exception:
        await ctx.bot.send_message(
            chat_id=update.effective_chat.id,
            text=panel_text,
            reply_markup=kb_admin(),
            parse_mode=ParseMode.HTML,
        )

async def cb_adm_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    sync_statuses()
    s = get_stats()
    sys_info = get_system_stats()
    uptime = fmt_duration((_now_ist() - START_TIME).total_seconds())
    lines = [
        f"👑 <b>System Statistics</b> 💎",
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈",
        f"",
        f"👤 <b>Total Users:</b>   <code>{s['users']}</code>",
        f"💎 <b>Premium Users:</b> <code>{s['premium']}</code>",
        f"📂 <b>Total Files:</b>   <code>{s['bots']}</code>",
        f"⚡ <b>Running:</b>       <code>{s['running']}</code>",
        f"⚠️ <b>Stopped/Error:</b> <code>{s['bots'] - s['running']}</code>",
        f"",
        f"🖥️ <b>Server</b>",
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈",
    ]
    if sys_info.get("server_name"):
        lines.append(f"🏷️ <b>Server Name:</b> <code>{h(sys_info['server_name'])}</code>")
    if sys_info.get("platform"):
        lines.append(f"☁️ <b>Platform:</b> <code>{h(sys_info['platform'])}</code>")
    lines.append(f"⏳ <b>Uptime:</b> <code>{h(uptime)}</code>")
    if sys_info.get("ram_used"):
        lines.append(f"🧠 <b>RAM:</b> <code>{sys_info['ram_used']} / {sys_info['ram_total']} ({sys_info['ram_pct']})</code>")
    if sys_info.get("disk_used"):
        lines.append(f"📀 <b>Disk:</b> <code>{sys_info['disk_used']} / {sys_info['disk_total']}</code>")
    lines.append(f"")
    # Sandbox status
    if _BWRAP_PATH:
        lines.append(f"🛡️ <b>Sandbox:</b> <code>bubblewrap (bwrap) ✅</code>")
    elif _FIREJAIL_PATH:
        lines.append(f"🛡️ <b>Sandbox:</b> <code>firejail ✅</code>")
    else:
        lines.append(f"🛡️ <b>Sandbox:</b> <code>resource limits only ⚠️</code>")
    lines.append(f"<b>{_now_ist():%d %b %Y %I:%M %p} IST</b>")
    await q.edit_message_text(
        "\n".join(lines),
        reply_markup=kb_back("adm_panel"),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_bot_mgmt(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    sync_statuses()
    bots = list(all_bots().values())
    total = len(bots)
    pending_count = sum(1 for b in bots if b.get("pending"))
    running = sum(1 for b in bots if b.get("status") == "running")
    stopped = sum(1 for b in bots if b.get("status") in ("stopped", "manually_stopped") and not b.get("pending"))
    error_count = sum(1 for b in bots if b.get("status") == "error" and not b.get("pending"))
    sec_blocked = sum(1 for b in bots if b.get("security_blocked") and not b.get("pending"))
    text = (
        "🧰 <b>Bots Management</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"📂 <b>Total Uploaded:</b> <code>{total}</code>\n"
        f"🟢 <b>Running:</b> <code>{running}</code>\n"
        f"🔴 <b>Stopped:</b> <code>{stopped}</code>\n"
        f"🟡 <b>Error:</b> <code>{error_count}</code>\n"
        f"🔒 <b>Security Blocked:</b> <code>{sec_blocked}</code>\n"
        f"⏳ <b>Pending Approval:</b> <code>{pending_count}</code>"
    )
    # This menu can be reached both from plain text menus AND from a
    # document/caption message (e.g. the "Approved & Started!" screen), so
    # edit whichever one actually applies -- edit_message_text fails silently
    # (raises, gets swallowed by PTB) when the source message is a document
    # with only a caption, which is why "Back" used to do nothing there.
    is_media_msg = bool(q.message and q.message.document)
    try:
        if is_media_msg:
            await q.edit_message_caption(text, reply_markup=kb_admin_bot_mgmt(), parse_mode=ParseMode.HTML)
        else:
            await q.edit_message_text(text, reply_markup=kb_admin_bot_mgmt(), parse_mode=ParseMode.HTML)
    except Exception:
        try:
            await ctx.bot.send_message(
                chat_id=update.effective_chat.id, text=text,
                reply_markup=kb_admin_bot_mgmt(), parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass

async def cb_adm_start_all(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    global _start_all_active
    if _start_all_active:
        await q.answer("⏳ Start All is already running…", show_alert=True)
        return
    _start_all_cancel.clear()
    _start_all_active = True
    await q.answer("Starting all bots…")
    await q.edit_message_text(
        "▶️ <b>Starting All Bots</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "⏳ Please wait, this may take a moment…\n"
        "🤖 Launching bots one by one to avoid overload.",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🛑 Cancel", callback_data="adm_cancel_start_all", style="danger")],
        ]),
        parse_mode=ParseMode.HTML,
    )

    async def _do_start_all():
        global _start_all_active
        try:
            result = await asyncio.to_thread(proc_start_all)

            errors = result["errors"][:5]
            truncated = any(len(e) >= 160 for e in result["errors"])
            if errors:
                err_lines = "\n".join(f"• {h(e)}" for e in errors)
                more = f"\n<b>…and {len(result['errors'])-5} more</b>" if len(result["errors"]) > 5 else ""
                logs_hint = "\n<b>See /logs for full error details.</b>" if truncated else ""
                error_block = (
                    f"\n\n⚠️ <b>First Errors</b>\n"
                    f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"{err_lines}{more}{logs_hint}"
                )
            else:
                error_block = ""

            usernames = result.get("usernames", [])
            if usernames:
                # Plain text (no <code>) so @usernames render as tappable
                # mentions that open the bot's own DM.
                uname_lines = "\n".join(f"• {h(u)}" for u in usernames[:30])
                more = f"\n<b>…and {len(usernames)-30} more</b>" if len(usernames) > 30 else ""
                uname_block = (
                    f"\n\n🤖 <b>Started Bots</b>\n"
                    f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"{uname_lines}{more}"
                )
            else:
                uname_block = ""

            cancelled_line = (
                f"🛑 <b>Cancelled       :</b> {result['cancelled']}\n" if result.get("cancelled") else ""
            )
            title = "🛑 <b>Start All Cancelled</b>" if result.get("was_cancelled") else "✅ <b>Start All Complete</b>"

            try:
                await q.edit_message_text(
                    f"{title}\n"
                    "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"✅ <b>Started        :</b> {result['started']}\n"
                    f"🟢 <b>Already Running :</b> {result['already']}\n"
                    f"⏳ <b>Skipped Pending :</b> {result['skipped']}\n"
                    f"{cancelled_line}"
                    f"❌ <b>Failed          :</b> {result['failed']}"
                    f"{uname_block}"
                    f"{error_block}",
                    reply_markup=kb_admin_bot_mgmt(),
                    parse_mode=ParseMode.HTML,
                )
            except Exception:
                pass
        finally:
            _start_all_active = False
            _start_all_cancel.clear()

    asyncio.create_task(_do_start_all())


async def cb_adm_cancel_start_all(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if not _start_all_active:
        await q.answer("Nothing to cancel — Start All isn't running.", show_alert=True)
        return
    _start_all_cancel.set()
    await q.answer("🛑 Cancelling… finishing the current bot, then stopping.", show_alert=True)

async def cb_adm_stop_all(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("Stopping all bots…")
    await q.edit_message_text("❌ <b>Stopping all bots…</b>\n\n<b>Please wait.</b>", parse_mode=ParseMode.HTML)
    result = proc_stop_all()
    errors = result["errors"][:5]
    error_text = ("\n\n<b>First errors:</b>\n" + "\n".join(f"• <code>{h(e)}</code>" for e in errors)) if errors else ""
    await q.edit_message_text(
        "❌ <b>Stop All Complete</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"✅ <b>Stopped:</b> <b>{result['stopped']}</b>\n"
        f"🔴 <b>Already Off:</b> <b>{result['already']}</b>\n"
        f"❌ <b>Failed:</b> <b>{result['failed']}</b>"
        f"{error_text}",
        reply_markup=kb_admin_bot_mgmt(),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_stopped_bots(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    sync_statuses()
    bots = {bid: b for bid, b in all_bots().items()
            if b.get("status") in ("stopped", "manually_stopped") and not b.get("pending")}
    if not bots:
        await q.edit_message_text(
            "🔴 <b>Stopped Bots</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            "<b>No stopped bots at the moment.</b>",
            reply_markup=kb_admin_bot_mgmt(), parse_mode=ParseMode.HTML,
        )
        return
    rows = []
    for bid, b in list(bots.items())[:30]:
        label = f"🔴 {b.get('file_name', bid)}"
        rows.append([InlineKeyboardButton(label, callback_data=f"adm_rbot_{bid}", style="primary")])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_bot_mgmt", style="primary")])
    await q.edit_message_text(
        f"🔴 <b>Stopped Bots</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>{len(bots)}</b> bot(s) stopped.\n<b>Select to manage:</b>",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )


async def cb_adm_error_bots(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    sync_statuses()
    bots = {bid: b for bid, b in all_bots().items()
            if b.get("status") == "error" and not b.get("pending")}
    if not bots:
        await q.edit_message_text(
            "🟡 <b>Error Bots</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            "<b>No bots with errors at the moment.</b>",
            reply_markup=kb_admin_bot_mgmt(), parse_mode=ParseMode.HTML,
        )
        return
    rows = []
    for bid, b in list(bots.items())[:30]:
        label = f"🟡 {b.get('file_name', bid)}"
        rows.append([InlineKeyboardButton(label, callback_data=f"adm_rbot_{bid}", style="primary")])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_bot_mgmt", style="primary")])
    await q.edit_message_text(
        f"🟡 <b>Error Bots</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>{len(bots)}</b> bot(s) with errors.\n<b>Select to manage:</b>",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )


async def cb_adm_security_bots(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id not in ADMIN_IDS:
        await q.answer("⛔ Admins only.", show_alert=True)
        return
    sync_statuses()
    bots = {bid: b for bid, b in all_bots().items()
            if b.get("security_blocked") and not b.get("pending")}
    if not bots:
        await q.edit_message_text(
            "🔒 <b>Security Blocked Bots</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            "<b>No bots are currently blocked by security.</b>",
            reply_markup=kb_admin_bot_mgmt(), parse_mode=ParseMode.HTML,
        )
        return
    rows = []
    for bid, b in list(bots.items())[:30]:
        fname  = b.get("file_name", bid)
        uid    = b.get("user_id", "?")
        reason = (b.get("security_block_reason") or "security scan")[:40]
        rows.append([InlineKeyboardButton(
            f"🔒 {fname}  (uid:{uid})",
            callback_data=f"adm_secbot_{bid}", style="primary",
        )])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_bot_mgmt", style="primary")])
    await q.edit_message_text(
        f"🔒 <b>Security Blocked Bots</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>{len(bots)}</b> bot(s) blocked by security scan.\n"
        f"<b>Select a bot to Force-Start it with admin power.</b>",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )


async def cb_adm_secbot(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id not in ADMIN_IDS:
        await q.answer("⛔ Admins only.", show_alert=True)
        return
    bid = q.data.split("adm_secbot_", 1)[1]
    b   = get_bot(bid)
    if not b:
        await q.edit_message_text("❌ Bot not found.", reply_markup=kb_back("adm_security_bots"))
        return
    reason  = b.get("security_block_reason") or "Unknown security block reason"
    fname   = b.get("file_name", bid)
    uid     = b.get("user_id", "?")
    status  = b.get("status", "error")
    text = (
        f"🔒 <b>Security Blocked Bot</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"📄 <b>File:</b>   <code>{h(fname)}</code>\n"
        f"👤 <b>User ID:</b> <code>{uid}</code>\n"
        f"📊 <b>Status:</b>  <code>{status}</code>\n\n"
        f"🛡 <b>Block Reason:</b>\n"
        f"<code>{h(reason)}</code>\n\n"
        f"⚠️ <b>Force-Start bypasses all security checks.\n"
        f"Only use this if you have personally reviewed the file.</b>"
    )
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("⚡ Force Start (Admin Power)", callback_data=f"adm_force_start_{bid}", style="success")],
        [InlineKeyboardButton("📋 View Logs",  callback_data=f"admbact_logs_{bid}", style="primary"),
         InlineKeyboardButton("🗑️ Delete",     callback_data=f"admbact_stop_{bid}", style="danger")],
        [InlineKeyboardButton("🔙 Back", callback_data="adm_security_bots", style="primary")],
    ])
    await q.edit_message_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)


async def cb_adm_force_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("⚡ Force-starting…")
    if update.effective_user.id not in ADMIN_IDS:
        await q.answer("⛔ Admins only.", show_alert=True)
        return
    bid = q.data.split("adm_force_start_", 1)[1]
    b   = get_bot(bid)
    if not b:
        await q.edit_message_text("❌ Bot not found.", reply_markup=kb_back("adm_security_bots"))
        return
    fname = b.get("file_name", bid)
    await q.edit_message_text(
        f"⚡ <b>Force-Starting Bot…</b>\n\n"
        f"📄 <code>{h(fname)}</code>\n\n"
        f"<b>Bypassing security checks — please wait.</b>",
        parse_mode=ParseMode.HTML,
    )

    async def _do_force():
        ok, msg = await asyncio.to_thread(proc_force_start, bid)
        result_text = (
            f"⚡ <b>Force-Start {'✅ Success' if ok else '❌ Failed'}</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📄 <code>{h(fname)}</code>\n\n"
            f"{msg}"
        )
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔒 Security Blocked List", callback_data="adm_security_bots", style="primary")],
            [InlineKeyboardButton("🧩 Bot Management",        callback_data="adm_bot_mgmt", style="primary")],
        ])
        try:
            await q.edit_message_text(result_text, reply_markup=kb, parse_mode=ParseMode.HTML)
        except Exception:
            pass

    asyncio.create_task(_do_force())


#  DYNAMIC PLANS HELPERS

def get_custom_plans() -> dict:
    """Load custom plans created by admin from the DB settings."""
    raw = get_setting("custom_plans", "")
    if not raw:
        return {}
    try:
        import json as _json
        return _json.loads(raw)
    except Exception:
        return {}

def save_custom_plans(plans: dict):
    """Persist custom plans dict to DB settings."""
    import json as _json
    upd_settings({"custom_plans": _json.dumps(plans)})

def get_all_plans() -> dict:
    """Return merged PLANS dict (built-in + custom admin-defined plans)."""
    merged = dict(PLANS)
    merged.update(get_custom_plans())
    return merged

#  ADMIN: DELETE ERROR FILES

async def cb_adm_del_error_files(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id not in ADMIN_IDS:
        await q.answer("Unauthorized.", show_alert=True)
        return

    async def _do_delete():
        await asyncio.to_thread(_delete_error_files_sync)
        try:
            sync_statuses()
            bots = all_bots()
            deleted = sum(
                1 for b in bots.values()
                if b.get("status") == "error" or not b.get("bot_token", "").strip()
            )
        except Exception:
            deleted = 0
        try:
            await q.edit_message_text(
                f"🗑️ <b>Delete Error Files — Done</b>\n"
                f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"✅ <b>Deleted:</b> <b>{_del_err_result.get('deleted',0)}</b> file(s) removed from disk + DB\n"
                f"⏭ <b>Skipped (no file):</b> <b>{_del_err_result.get('skipped',0)}</b>\n\n"
                f"<b>Removed files and DB entries for bots with errors or missing tokens.</b>",
                reply_markup=kb_admin_bot_mgmt(),
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass

    _del_err_result = {}

    def _delete_error_files_sync():
        sync_statuses()
        bots = all_bots()
        deleted = 0
        skipped = 0
        for bid, b in list(bots.items()):
            status = b.get("status", "off")
            tok = b.get("bot_token", "").strip()
            fp = b.get("file_path", "")
            has_file = bool(fp) and (
                os.path.exists(fp) or
                os.path.exists(fp + ".enc")
            )
            if not has_file and tok:
                skipped += 1
                continue
            if status == "error" or not tok:
                try:
                    proc_stop(bid)
                except Exception:
                    pass
                remove_bot_file(b)
                del_bot(bid)
                deleted += 1
        _del_err_result["deleted"] = deleted
        _del_err_result["skipped"] = skipped

    await q.edit_message_text(
        "🗑️ <b>Deleting error files…</b>\n\n<b>Running in background — please wait.</b>",
        parse_mode=ParseMode.HTML,
    )
    asyncio.create_task(_do_delete())

#  ADMIN: DELETE STOPPED BOTS — manual button deletes free-plan bots that
#  have sat stopped for 3+ days; a background loop (below) does the same
#  automatically after 7 days. Paid-plan bots are never touched by either.

def _bot_stopped_duration_days(b: dict) -> Optional[float]:
    """Days since this bot's status last flipped to stopped/manually_stopped.
    Returns None if we have no stopped_at timestamp (e.g. legacy entries)."""
    ts = b.get("stopped_at")
    if not ts:
        return None
    try:
        return (_now_ist() - _parse_dt(ts)).total_seconds() / 86400.0
    except Exception:
        return None

def _delete_stopped_bots_sync(min_days: float, free_only: bool = True) -> dict:
    """Delete stopped bots (file + DB entry) that have been stopped for at
    least `min_days`. When free_only is True, paid-plan users' bots are
    skipped no matter how long they've been stopped."""
    sync_statuses()
    bots = all_bots()
    result = {"deleted": 0, "skipped_recent": 0, "skipped_paid": 0}
    for bid, b in list(bots.items()):
        if b.get("pending"):
            continue
        if b.get("status") not in ("stopped", "manually_stopped"):
            continue
        days = _bot_stopped_duration_days(b)
        if days is None or days < min_days:
            result["skipped_recent"] += 1
            continue
        if free_only:
            uid = b.get("user_id")
            if uid is not None and not _is_free_user(int(uid)):
                result["skipped_paid"] += 1
                continue
        try:
            proc_stop(bid)
        except Exception:
            pass
        remove_bot_file(b)
        del_bot(bid)
        result["deleted"] += 1
    return result

_DEL_STOPPED_MANUAL_MIN_DAYS = 3.0

async def cb_adm_del_stopped_bots(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id not in ADMIN_IDS:
        await q.answer("Unauthorized.", show_alert=True)
        return

    async def _do_delete():
        result = await asyncio.to_thread(_delete_stopped_bots_sync, _DEL_STOPPED_MANUAL_MIN_DAYS, True)
        try:
            await q.edit_message_text(
                f"🗑️ <b>Delete Stopped Bots — Done</b>\n"
                f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"✅ <b>Deleted:</b> <b>{result['deleted']}</b> bot(s) — free plan, stopped ≥3 days\n"
                f"⏭ <b>Skipped (stopped &lt;3 days):</b> <b>{result['skipped_recent']}</b>\n"
                f"💎 <b>Skipped (paid plan):</b> <b>{result['skipped_paid']}</b>\n\n"
                f"<b>Only free-plan bots stopped for 3+ days are eligible.</b>",
                reply_markup=kb_admin_bot_mgmt(),
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass

    await q.edit_message_text(
        "🗑️ <b>Deleting stopped bots…</b>\n\n<b>Running in background — please wait.</b>",
        parse_mode=ParseMode.HTML,
    )
    asyncio.create_task(_do_delete())

#  ADMIN: NEW PLAN

async def cb_adm_new_plan(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id not in ADMIN_IDS:
        await q.answer("Unauthorized.", show_alert=True)
        return
    set_st(ctx, "adm_new_plan_name")
    await q.edit_message_text(
        "➕ <b>New Plan — Step 1/4</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "📝 <b>Send the plan name.</b>\n"
        "<b>Example: Gold, Silver, Pro</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )

#  ADMIN: MANAGE PLANS

async def cb_adm_manage_plans(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id not in ADMIN_IDS:
        await q.answer("Unauthorized.", show_alert=True)
        return
    all_pl = get_all_plans()

    def _mp_price_key(item):
        pk, pl = item
        if pk == "free":
            return -1
        price_str = pl.get("price", "")
        m = re.search(r"[\d,]+", price_str.replace(",", ""))
        try:
            return float(m.group().replace(",", "")) if m else 9999999
        except Exception:
            return 9999999

    sorted_plans = sorted(all_pl.items(), key=_mp_price_key)
    rows = []
    for pk, pl in sorted_plans:
        lim = pl.get("file_limit", 0)
        lim_str = "♾️" if lim == UNLIMITED_SENTINEL else str(lim)
        ram = pl.get("ram_mb", 0)
        ram_str = "♾️" if ram == UNLIMITED_SENTINEL else (f"{ram/1024:g}GB" if ram >= 1024 else f"{ram}MB")
        approval = "✅" if pl.get("approval", False) else "🔓"
        label = f"{pl.get('emoji','📦')} {pl.get('name', pk)} — {pl.get('price','N/A')} | {lim_str} files | {ram_str} RAM | {approval}"
        rows.append([InlineKeyboardButton(label, callback_data=f"adm_mplan_{pk}", style="primary")])
    rows.append([InlineKeyboardButton("➕ New Plan", callback_data="adm_new_plan", style="primary")])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")])
    await q.edit_message_text(
        "🔧 <b>Manage Plans</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "<b>Plans sorted by price (low → high).\nSelect a plan to edit price, duration, file limit, or approval:</b>",
        reply_markup=InlineKeyboardMarkup(rows),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_mplan(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id not in ADMIN_IDS:
        await q.answer("Unauthorized.", show_alert=True)
        return
    plan_key = q.data.split("adm_mplan_", 1)[1]
    all_pl = get_all_plans()
    if plan_key not in all_pl:
        await q.answer("Plan not found.", show_alert=True)
        return
    pl = all_pl[plan_key]
    lim = pl.get("file_limit", 0)
    lim_str = "Unlimited" if lim == UNLIMITED_SENTINEL else str(lim)
    ram = pl.get("ram_mb", 0)
    ram_str = "Unlimited" if ram == UNLIMITED_SENTINEL else f"{ram} MB"
    approval_str = "Yes" if pl.get("approval", False) else "No"
    set_st(ctx, "adm_edit_plan_price", edit_plan_key=plan_key)
    await q.edit_message_text(
        f"🔧 <b>Edit Plan: {pl.get('emoji','')} {pl.get('name', plan_key)}</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"💰 <b>Current Price:</b> {pl.get('price','N/A')}\n"
        f"📅 <b>Current Duration:</b> {pl.get('duration_days', 'N/A')} day(s)\n"
        f"📁 <b>Current File Limit:</b> {lim_str}\n"
        f"🧠 <b>Current RAM Limit:</b> {ram_str}\n"
        f"✅ <b>Approval Required:</b> {approval_str}\n\n"
        f"<b>Step 1/4 — 💬 Send the new price</b> (e.g. <code>₹149 / Month</code> or keep same, send <code>-</code> to skip):",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_manage_plans", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_running(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    sync_statuses()
    running = [b for b in all_bots().values() if _live_status(b) == "running"]
    if not running:
        await q.edit_message_text(
            "🤖 <b>Running Bots</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>No bots currently running.</b>",
            reply_markup=kb_admin_bot_mgmt(), parse_mode=ParseMode.HTML,
        )
        return
    rows = []
    for b in running:
        uid_s = str(b["user_id"])
        u = get_user(int(uid_s))
        uname = f"@{u['username']}" if u and u.get("username") else (u.get("first_name","") if u else f"uid:{uid_s}")
        rows.append([InlineKeyboardButton(
            f"🟢 {h(b['file_name'])} ({h(uname)})",
            callback_data=f"adm_rbot_{b['bot_id']}"
        , style="primary")])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_bot_mgmt", style="primary")])
    await q.edit_message_text(
        f"🤖 <b>Running Bots</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>{len(running)}</b> active:",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )

async def cb_adm_rbot(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    bid = q.data.split("adm_rbot_",1)[1]
    b   = get_bot(bid)
    if not b:
        await q.edit_message_text("❌ Not found.", reply_markup=kb_back("adm_running"))
        return
    s   = b.get("status","stopped")
    pid = b.get("pid")
    proc_info = get_bot_proc_info(bid)
    bot_username = await auto_fetch_bot_username(
        get_decrypted_bot_token(b) or extract_bot_token(b.get("file_path",""))
    )
    username_line = f"🤖 <b>Bot Username:</b> @{h(bot_username)}\n" if bot_username else ""
    owner = get_user(b["user_id"])
    plan_key = (owner or {}).get("plan", "free")
    pl = PLANS.get(plan_key, PLANS["free"])
    plan_str = f"{pl.get('emoji','')} {pl.get('name', plan_key)}"
    text = (
        f"🤖 <b>Bot (Admin View)</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"📄 <b>File:</b>   <code>{h(b['file_name'])}</code>\n"
        f"👤 <b>User:</b>   <code>{b['user_id']}</code> ({plan_str})\n"
        f"{username_line}"
        f"📊 <b>Status:</b> {si(s)}\n"
    )
    if pid:
        text += f"⚙️ <b>PID:</b>    <code>{pid}</code>\n"
    if s == "running":
        text += f"⏱️ <b>Uptime:</b> <code>{h(bot_uptime(b))}</code>\n"
        ram_str = proc_info.get("ram") or "N/A"
        text += f"🧠 <b>Ram Used:</b> <code>{ram_str}</code>\n"
        if proc_info.get("cpu"):
            text += f"⚙️ <b>CPU:</b>    <code>{proc_info['cpu']}</code>\n"
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("▶️ Start",      callback_data=f"admbact_start_{bid}", style="success"),
         InlineKeyboardButton("❌ Stop",        callback_data=f"admbact_stop_{bid}", style="danger"),
         InlineKeyboardButton("🔄 Restart",    callback_data=f"admbact_restart_{bid}", style="primary")],
        [InlineKeyboardButton("📋 Logs",       callback_data=f"admbact_logs_{bid}", style="primary"),
         InlineKeyboardButton("💾 Save",       callback_data=f"admbact_save_{bid}", style="success")],
        [InlineKeyboardButton("🔁 Replace File", callback_data=f"adm_replace_pick_{bid}", style="primary"),
         InlineKeyboardButton("👤 Transfer",   callback_data=f"admbact_transfer_{bid}", style="primary")],
        [InlineKeyboardButton("🔙 Back",       callback_data="adm_running", style="primary")],
    ])
    await q.edit_message_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)

async def cb_admbact(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    parts = q.data.split("_",2)
    if len(parts) < 3:
        return
    action, bid = parts[1], parts[2]
    if action == "logs":
        logs_md = format_logs_md2(bid)
        await q.edit_message_text(
            logs_md,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄 Refresh",    callback_data=f"admbact_logs_{bid}", style="primary"),
                 InlineKeyboardButton("📡 Live Logs", callback_data=f"bact_livelogs_{bid}", style="primary")],
                [InlineKeyboardButton("🔙 Back",       callback_data=f"adm_rbot_{bid}", style="primary")],
            ]),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return
    if action == "save":
        b = get_bot(bid)
        if not b:
            await q.answer("❌ Not found.", show_alert=True)
            return
        send_fp = get_sendable_file_path(b)
        if not send_fp:
            await q.answer("❌ File not found on disk.", show_alert=True)
            return
        stored_fp = b.get("file_path","")
        _tmp_created = (send_fp != stored_fp and os.path.exists(send_fp))
        bk = os.path.join(BACKUP_DIR, str(b["user_id"]))
        os.makedirs(bk, exist_ok=True)
        try:
            shutil.copy2(send_fp, os.path.join(bk, b["file_name"]))
        except Exception:
            pass
        try:
            with open(send_fp,"rb") as f:
                await ctx.bot.send_document(
                    chat_id=OWNER_ID, document=f, filename=b["file_name"],
                    caption=f"💾 <b>Saved File</b>\n👤 <code>{b['user_id']}</code>\n📄 <code>{h(b['file_name'])}</code>",
                    parse_mode=ParseMode.HTML,
                )
            await q.answer("✅ File sent to your DM!", show_alert=True)
        except Exception as e:
            await q.answer(f"❌ {e}", show_alert=True)
        finally:
            if _tmp_created and os.path.exists(send_fp):
                try:
                    os.remove(send_fp)
                except Exception:
                    pass
        return
    if action == "transfer":
        set_st(ctx, "adm_transfer_bot", transfer_bid=bid)
        b = get_bot(bid)
        fname = b.get("file_name","") if b else bid
        await q.edit_message_text(
            f"👤 <b>Transfer Bot Ownership (Admin)</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📄 <b>Bot:</b> <code>{h(fname)}</code>\n\n"
            f"<b>Send the User ID of the new owner.</b>",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data=f"adm_rbot_{bid}", style="danger")]]),
            parse_mode=ParseMode.HTML,
        )
        return
    if action == "stop":      proc_stop(bid)
    elif action == "restart": await asyncio.get_running_loop().run_in_executor(None, proc_restart, bid)
    elif action == "start":   await asyncio.get_running_loop().run_in_executor(None, proc_start, bid)
    b2 = get_bot(bid)
    msg = f"✅ <b>Action '{action}' done.</b>"
    await q.edit_message_text(msg, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Running Bots", callback_data="adm_running", style="primary")]]), parse_mode=ParseMode.HTML)


async def cb_adm_pending(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    pending = pending_bots()
    if not pending:
        await q.edit_message_text(
            "⏳ <b>Pending Approvals</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>No pending uploads.</b>",
            reply_markup=kb_back("adm_panel"),
            parse_mode=ParseMode.HTML,
        )
        return
    rows = []
    for b in pending[:40]:
        uid_s = str(b.get("user_id"))
        u = get_user(int(uid_s))
        rows.append([InlineKeyboardButton(
            f"⏳ {h(b['file_name'])} — {h(user_display(uid_s, u))}",
            callback_data=f"adm_fdet_{uid_s}_{b['bot_id']}", style="primary",
        )])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")])
    await q.edit_message_text(
        f"⏳ <b>Pending Approvals</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>{len(pending)}</b> upload(s) awaiting review:",
        reply_markup=InlineKeyboardMarkup(rows),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_users_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    users = all_users()
    total = len(users)
    premium_count = sum(
        1 for u in users.values() if u.get("plan", "free") not in ("free", None)
    )
    banned_count = len(_load().get("bans", []))
    custom_ram_count = sum(1 for u in users.values() if u.get("custom_ram_mb") is not None)
    rows = [
        [InlineKeyboardButton(f"👥 All Users ({total})",        callback_data="adm_users",         style="primary"),
         InlineKeyboardButton(f"💎 Premium Users ({premium_count})", callback_data="adm_premium_users", style="success")],
        [InlineKeyboardButton(f"🧠 Custom RAM ({custom_ram_count})", callback_data="adm_customram_users", style="primary"),
         InlineKeyboardButton(f"🚫 Banned Users ({banned_count})",   callback_data="adm_banned_users",  style="danger")],
        [InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")],
    ]
    await q.edit_message_text(
        f"👥 <b>Users</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>{total}</b> registered total.\n"
        f"Choose a category to view:",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )

async def cb_adm_customram_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    page = 0
    if q.data.startswith("adm_customram_users_page_"):
        try:
            page = int(q.data.split("adm_customram_users_page_", 1)[1])
        except ValueError:
            page = 0
    users = all_users()
    cram_items = [
        (uid, u) for uid, u in users.items()
        if u.get("custom_ram_mb") is not None
    ]
    if not cram_items:
        await q.edit_message_text(
            "🧠 <b>No users with a custom RAM allowance yet.</b>",
            reply_markup=kb_back("adm_users_menu"), parse_mode=ParseMode.HTML,
        )
        return
    PAGE_SIZE = 20
    total_pages = max(1, (len(cram_items) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, total_pages - 1))
    slice_ = cram_items[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]
    rows = []
    for uid, u in slice_:
        cram = u.get("custom_ram_mb")
        cram_str = "Unlimited ♾️" if cram == UNLIMITED_SENTINEL else f"{cram} MB"
        rows.append([InlineKeyboardButton(f"🧠 {h(user_display(uid, u))} — {cram_str}", callback_data=f"adm_user_{uid}", style="primary")])
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("◀️ Prev", callback_data=f"adm_customram_users_page_{page-1}", style="primary"))
    if page < total_pages - 1:
        nav.append(InlineKeyboardButton("Next ▶️", callback_data=f"adm_customram_users_page_{page+1}", style="primary"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton("🔙 Users", callback_data="adm_users_menu", style="primary")])
    await q.edit_message_text(
        f"🧠 <b>Custom RAM Users</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>{len(cram_items)}</b> user(s) with a custom RAM override  |  Page <b>{page+1}</b>/<b>{total_pages}</b>:",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )

async def cb_adm_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    page = 0
    if q.data.startswith("adm_users_page_"):
        try:
            page = int(q.data.split("adm_users_page_", 1)[1])
        except ValueError:
            page = 0
    users = all_users()
    if not users:
        await q.edit_message_text("👥 <b>No users yet.</b>", reply_markup=kb_back("adm_users_menu"), parse_mode=ParseMode.HTML)
        return
    PAGE_SIZE = 20
    items = list(users.items())
    total_pages = max(1, (len(items) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, total_pages - 1))
    slice_ = items[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]
    rows = []
    for uid, u in slice_:
        p = u.get("plan","free")
        if p not in PLANS:
            p = "free"
        rows.append([InlineKeyboardButton(f"{PLANS[p]['emoji']} {h(user_display(uid, u))} [{p}]", callback_data=f"adm_user_{uid}", style="primary")])
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("◀️ Prev", callback_data=f"adm_users_page_{page-1}", style="primary"))
    if page < total_pages - 1:
        nav.append(InlineKeyboardButton("Next ▶️", callback_data=f"adm_users_page_{page+1}", style="primary"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton("🔍 Find User by ID", callback_data="adm_find_user_id", style="primary")])
    rows.append([InlineKeyboardButton("🔙 Users", callback_data="adm_users_menu", style="primary")])
    await q.edit_message_text(
        f"👥 <b>All Users</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>{len(users)}</b> registered  |  Page <b>{page+1}</b>/<b>{total_pages}</b>:",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )

async def cb_adm_premium_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    page = 0
    if q.data.startswith("adm_premium_users_page_"):
        try:
            page = int(q.data.split("adm_premium_users_page_", 1)[1])
        except ValueError:
            page = 0
    users = all_users()
    premium_items = [
        (uid, u) for uid, u in users.items()
        if u.get("plan", "free") not in ("free", None)
    ]
    if not premium_items:
        await q.edit_message_text(
            "💎 <b>No premium users yet.</b>",
            reply_markup=kb_back("adm_users_menu"), parse_mode=ParseMode.HTML,
        )
        return
    PAGE_SIZE = 20
    total_pages = max(1, (len(premium_items) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, total_pages - 1))
    slice_ = premium_items[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]
    rows = []
    for uid, u in slice_:
        p = u.get("plan", "free")
        if p not in PLANS:
            p = "free"
        rows.append([InlineKeyboardButton(f"{PLANS[p]['emoji']} {h(user_display(uid, u))} [{p}]", callback_data=f"adm_user_{uid}", style="success")])
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("◀️ Prev", callback_data=f"adm_premium_users_page_{page-1}", style="primary"))
    if page < total_pages - 1:
        nav.append(InlineKeyboardButton("Next ▶️", callback_data=f"adm_premium_users_page_{page+1}", style="primary"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton("🔙 Users", callback_data="adm_users_menu", style="primary")])
    await q.edit_message_text(
        f"💎 <b>Premium Users</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>{len(premium_items)}</b> on a paid plan  |  Page <b>{page+1}</b>/<b>{total_pages}</b>:",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )

async def cb_adm_banned_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    page = 0
    if q.data.startswith("adm_banned_users_page_"):
        try:
            page = int(q.data.split("adm_banned_users_page_", 1)[1])
        except ValueError:
            page = 0
    ban_ids = [str(b) for b in _load().get("bans", [])]
    if not ban_ids:
        await q.edit_message_text(
            "🚫 <b>No banned users.</b>",
            reply_markup=kb_back("adm_users_menu"), parse_mode=ParseMode.HTML,
        )
        return
    PAGE_SIZE = 20
    total_pages = max(1, (len(ban_ids) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, total_pages - 1))
    slice_ = ban_ids[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]
    rows = []
    for uid in slice_:
        u = get_user(int(uid)) if uid.isdigit() else None
        label = h(user_display(uid, u)) if u else f"User ({uid})"
        rows.append([InlineKeyboardButton(f"🚫 {label} [{uid}]", callback_data=f"adm_user_{uid}", style="danger")])
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("◀️ Prev", callback_data=f"adm_banned_users_page_{page-1}", style="primary"))
    if page < total_pages - 1:
        nav.append(InlineKeyboardButton("Next ▶️", callback_data=f"adm_banned_users_page_{page+1}", style="primary"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton("🔙 Users", callback_data="adm_users_menu", style="primary")])
    await q.edit_message_text(
        f"🚫 <b>Banned Users</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>{len(ban_ids)}</b> banned  |  Page <b>{page+1}</b>/<b>{total_pages}</b>:",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )

async def cb_adm_find_user_id(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "adm_find_user_id")
    await q.edit_message_text(
        "🔍 <b>Find User by ID</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "<b>Send the Telegram User ID</b> you want to look up:\n"
        "<b>Example: <code>123456789</code></b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )

async def _render_adm_user_det(q, uid_s: str):
    u = get_user(int(uid_s))
    if not u:
        await q.edit_message_text("❌ User not found.", reply_markup=kb_back("adm_users"))
        return
    banned = is_banned(int(uid_s))
    p = u.get("plan","free")
    if p not in PLANS:
        p = "free"
    pl = PLANS[p]
    override = u.get("approval_override")
    approval_status = "Enabled (override)" if override is True else ("Disabled (override)" if override is False else "Default")
    custom_ram = u.get("custom_ram_mb")
    if custom_ram is not None:
        ram_lim_str = ("Unlimited ♾️" if custom_ram == UNLIMITED_SENTINEL else f"{custom_ram} MB") + " <b>(custom)</b>"
    else:
        ram_lim_str = ("Unlimited ♾️" if pl.get("ram_mb", 0) == UNLIMITED_SENTINEL else f"{pl.get('ram_mb', 0)} MB") + " <b>(plan default)</b>"
    text = (
        f"👤 <b>User Profile</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"👤 <b>Name:</b>     {h(user_display(uid_s, u))}\n"
        f"🆔 <b>ID:</b>       <code>{uid_s}</code>\n"
        f"👤 <b>Username:</b> @{h(u.get('username') or 'N/A')}\n"
        f"{pl['emoji']} <b>Plan:</b>     <b>{pl['name']}</b>\n"
        f"📅 <b>Expiry:</b>   {fmt_expiry(u.get('expiry'))}\n"
        f"📁 <b>Files:</b>    <b>{len(u.get('bots',[]))}</b>\n"
        f"🧠 <b>RAM Limit:</b> <b>{ram_lim_str}</b>\n"
        f"🛡 <b>Approval:</b> <b>{approval_status}</b>\n"
        f"🚫 <b>Banned:</b>   {'<b>Yes</b>' if banned else 'No'}"
    )
    ban_btn = (
        InlineKeyboardButton("✅ Unban", callback_data=f"adm_unban_id_{uid_s}", style="success")
        if banned else
        InlineKeyboardButton("🚫 Ban",   callback_data=f"adm_ban_id_{uid_s}", style="danger")
    )
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("📂 View Files", callback_data=f"adm_ufiles_{uid_s}", style="primary"),
         InlineKeyboardButton("🎁 Give Sub",   callback_data=f"adm_givesub_{uid_s}", style="success")],
        [InlineKeyboardButton("✅ Enable Approval",  callback_data=f"adm_set_approval_{uid_s}_on", style="success"),
         InlineKeyboardButton("❌ Disable Approval", callback_data=f"adm_set_approval_{uid_s}_off", style="primary")],
        [ban_btn,
         InlineKeyboardButton("🧠 Add Custom RAM", callback_data=f"adm_customram_set_{uid_s}", style="primary")],
        [InlineKeyboardButton("♻️ Revoke Custom RAM", callback_data=f"adm_customram_revoke_{uid_s}", style="danger")],
        [InlineKeyboardButton("🔙 Users", callback_data="adm_users_menu", style="primary")],
    ])
    await q.edit_message_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)

async def cb_adm_user_det(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid_s = q.data.split("adm_user_",1)[1]
    await _render_adm_user_det(q, uid_s)

async def cb_adm_set_approval(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    rest = q.data.split("adm_set_approval_",1)[1]
    uid_s, flag = rest.rsplit("_",1)
    value = True if flag == "on" else False
    upd_user(int(uid_s), {"approval_override": value})
    status_word = "Enabled" if value else "Disabled"
    await q.edit_message_text(
        f"✅ <b>Approval {status_word} for User</b>\n\n"
        f"<code>{uid_s}</code> — approval is now <b>{status_word.lower()}</b> (override).",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 User Profile", callback_data=f"adm_user_{uid_s}", style="primary"),
             InlineKeyboardButton("👥 All Users",    callback_data="adm_users", style="primary")],
        ]), parse_mode=ParseMode.HTML,
    )


async def cb_adm_approval_toggle(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    current = get_setting("approval_required_all", True)
    await q.edit_message_text(
        f"✅ <b>Admin Approval Toggle</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>Current status:</b> {'🔒 <b>Enabled</b> (all free users need approval)' if current else '🔓 <b>Disabled</b> (no approval needed)'}\n\n"
        f"<b>You can also set per-user overrides from each user's profile.</b>",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔒 Enable (All Need Approval)",  callback_data="adm_approval_set_on", style="success"),
             InlineKeyboardButton("🔓 Disable (No Approval)",       callback_data="adm_approval_set_off", style="primary")],
            [InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")],
        ]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_approval_set(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    flag = q.data.split("adm_approval_set_",1)[1]
    value = flag == "on"
    upd_settings({"approval_required_all": value})
    word = "Enabled" if value else "Disabled"
    await q.edit_message_text(
        f"✅ <b>Approval {word} for All</b>\n\n"
        f"<b>Admin approval is now <b>{'required' if value else 'not required'}</b> for all users by default.</b>",
        reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
    )


async def cb_adm_force_join(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    fj = get_setting("force_join", False)
    # Always show hardcoded channels first
    ch_list = "\n  <b>── Hardcoded (always on) ──</b>"
    for ch in HARDCODED_FJ_CHANNELS:
        ch_list += f"\n  • <b>{h(ch.get('title',''))}</b> → {h(ch.get('username',''))} — <a href=\"{h(ch.get('link',''))}\">link</a>"
    # Admin-added channels
    db_channels = get_setting("force_join_channels", [])
    if not isinstance(db_channels, list):
        db_channels = []
    if db_channels:
        ch_list += "\n\n  <b>── Admin-Added ──</b>"
        for i, ch in enumerate(db_channels):
            title = ch.get("title", ch.get("username", f"Channel {i+1}"))
            ch_list += f"\n  {i+1}. <b>{h(title)}</b> → {h(ch.get('username',''))} — <a href=\"{h(ch.get('link',''))}\">link</a>"
    else:
        ch_list += "\n\n  <b>No admin-added channels.</b>"
    await q.edit_message_text(
        f"🔒 <b>Force Join Settings</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>Status:</b> {'🟢 <b>Enabled</b>' if fj else '🔴 <b>Disabled</b>'}\n\n"
        f"<b>Channels:</b>\n{ch_list}\n\n"
        f"<b>When enabled, users must join ALL channels to use the bot.\n"
        f"Hardcoded channels are always enforced when Force Join is ON.</b>",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Enable",       callback_data="adm_fj_on", style="success"),
             InlineKeyboardButton("❌ Disable",      callback_data="adm_fj_off", style="primary")],
            [InlineKeyboardButton("➕ Add Channel",  callback_data="adm_fj_add_channel", style="success"),
             InlineKeyboardButton("🗑️ Remove Channel", callback_data="adm_fj_remove_channel", style="danger")],
            [InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")],
        ]),
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )

async def cb_adm_fj_toggle(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    flag = q.data == "adm_fj_on"
    upd_settings({"force_join": flag})
    word = "Enabled" if flag else "Disabled"
    await q.edit_message_text(
        f"✅ <b>Force Join {word}</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Force Join", callback_data="adm_force_join", style="success")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_fj_add_channel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "adm_fj_add_channel_title")
    await q.edit_message_text(
        "➕ <b>Add Force Join Channel — Step 1/2</b>\n\n"
        "<b>Send the button title</b> that users will see:\n\n"
        "<b>Example: <code>Updates Channel</code> or <code>Bots Hub</code></b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_force_join", style="success")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_fj_remove_channel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    db_channels = get_setting("force_join_channels", [])
    if not isinstance(db_channels, list):
        db_channels = []
    if not db_channels:
        await q.answer("No admin-added channels to remove. Hardcoded channels cannot be removed.", show_alert=True)
        return
    rows = []
    for i, ch in enumerate(db_channels):
        title = ch.get("title", ch.get("username", f"Channel {i+1}"))
        rows.append([InlineKeyboardButton(
            f"🗑️ {title} ({ch.get('username', '')})",
            callback_data=f"adm_fj_del_{i}"
        , style="danger")])
    rows.append([InlineKeyboardButton("❌ Cancel", callback_data="adm_force_join", style="success")])
    await q.edit_message_text(
        "🗑️ <b>Remove Admin-Added Force Join Channel</b>\n\n"
        "<b>Note: Hardcoded channels cannot be removed here.</b>\n\n"
        "Select channel to remove:",
        reply_markup=InlineKeyboardMarkup(rows),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_fj_del(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    idx = int(q.data.split("adm_fj_del_",1)[1])
    remove_force_join_channel(idx)
    await q.edit_message_text(
        "✅ <b>Channel removed from force join list.</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Force Join", callback_data="adm_force_join", style="success")]]),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_ban(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "adm_ban")
    await q.edit_message_text(
        "🚫 <b>Ban User</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\nSend the <b>User ID</b> to ban:",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_unban(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "adm_unban")
    await q.edit_message_text(
        "✅ <b>Unban User</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\nSend the <b>User ID</b> to unban:",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_ban_id(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid_s = q.data.split("adm_ban_id_",1)[1]
    ban_user(int(uid_s))
    try:
        await ctx.bot.send_message(
            chat_id=int(uid_s),
            text=(
                "<b>🚫 Access Revoked</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                "<b>You have been banned from this bot.</b>\n\n"
                "<b>All actions are now blocked. Contact the owner if you believe this is a mistake.</b>"
            ),
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        pass
    _bu = get_user(int(uid_s))
    _uname = f"@{h(_bu['username'])}" if _bu and _bu.get("username") else (h(_bu.get("first_name","")) if _bu else f"uid:{uid_s}")
    await q.edit_message_text(
        (
            "<b>🚫 User Banned</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"<b>👤 User:     {_uname}</b>\n"
            f"<b>🆔 User ID:  {uid_s}</b>\n"
            "<b>📊 Status:   Banned</b>\n\n"
            "<b>They've been notified and blocked from all actions.</b>"
        ),
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 User Profile", callback_data=f"adm_user_{uid_s}", style="primary"),
             InlineKeyboardButton("👥 All Users",    callback_data="adm_users", style="primary")],
        ]), parse_mode=ParseMode.HTML,
    )

async def cb_adm_unban_id(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid_s = q.data.split("adm_unban_id_",1)[1]
    unban_user(int(uid_s))
    try:
        await ctx.bot.send_message(
            chat_id=int(uid_s),
            text=(
                "<b>✅ Access Restored</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                "<b>You have been unbanned from this bot.</b>\n\n"
                "<b>Welcome back — you can use the bot again.</b>"
            ),
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        pass
    _bu = get_user(int(uid_s))
    _uname = f"@{h(_bu['username'])}" if _bu and _bu.get("username") else (h(_bu.get("first_name","")) if _bu else f"uid:{uid_s}")
    await q.edit_message_text(
        (
            "<b>✅ User Unbanned</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"<b>👤 User:     {_uname}</b>\n"
            f"<b>🆔 User ID:  {uid_s}</b>\n"
            "<b>📊 Status:   Active</b>\n\n"
            "<b>Access has been restored.</b>"
        ),
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔙 User Profile", callback_data=f"adm_user_{uid_s}", style="primary"),
             InlineKeyboardButton("👥 All Users",    callback_data="adm_users", style="primary")],
        ]), parse_mode=ParseMode.HTML,
    )


async def cb_adm_broadcast(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "adm_broadcast")
    await q.edit_message_text(
        "📢 <b>Bʀᴏᴀᴅᴄᴀꜱᴛ Mᴇꜱꜱᴀɢᴇ</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "Sᴇɴᴅ Yᴏᴜʀ Mᴇꜱꜱᴀɢᴇ Nᴏᴡ. 😶‍🌫️",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_bc_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("Broadcast cancelled.")
    clr_st(ctx)
    await q.edit_message_text(
        "❌ <b>Broadcast cancelled.</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
        parse_mode=ParseMode.HTML,
    )

async def _do_broadcast(bot, src_chat: int, src_mid: int, src_preview: str, pm) -> None:
    """Background task: sends the broadcast to HOSTING BOT users only.

    Reads all_users() = d["users"] — people who /start'd this hosting bot.
    hosted_bot_users (end-users of each hosted bot) are NOT in this list and
    are NEVER included here.  Use Bot Broadcast (adm_bot_broadcast) for those.
    Bot owners of hosted bots are excluded from recipients.
    """
    bans = set(str(b) for b in _load().get("bans", []))
    # Collect IDs of hosted bot owners to exclude them
    bot_owner_ids = {str(b["user_id"]) for b in all_bots().values() if b.get("user_id")}
    recipients = []
    seen: set = set()
    # all_users() → d["users"] → HOSTING BOT users only
    for u_str in all_users().keys():
        try:
            u_int = int(u_str)
        except (TypeError, ValueError):
            continue
        if str(u_int) in bans or u_int in seen or str(u_int) in bot_owner_ids:
            continue
        seen.add(u_int)
        recipients.append(u_int)
    total = len(recipients)
    if not total:
        try:
            await pm.edit_text("⚠️ <b>No recipients.</b>",
                               reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML)
        except Exception:
            pass
        return
    try:
        await pm.edit_text(
            f"📡 <b>Broadcasting…</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"👥 <b>Recipients:</b> <b>{total}</b>\n📨 <b>Sent:</b> <b>0</b>",
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        pass
    sent = failed = blocked = 0
    sent_map: dict = {}
    failed_map: dict = {}
    last_progress = 0
    for idx, u_id in enumerate(recipients, 1):
        try:
            mid_obj = await bot.copy_message(chat_id=u_id, from_chat_id=src_chat, message_id=src_mid)
            sent_map[str(u_id)] = mid_obj.message_id
            sent += 1
        except Forbidden:
            blocked += 1
            failed += 1
            failed_map[str(u_id)] = "blocked"
        except RetryAfter as e:
            try:
                await asyncio.sleep(getattr(e, "retry_after", 2) + 0.5)
                mid_obj = await bot.copy_message(chat_id=u_id, from_chat_id=src_chat, message_id=src_mid)
                sent_map[str(u_id)] = mid_obj.message_id
                sent += 1
            except Exception as retry_err:
                failed += 1
                failed_map[str(u_id)] = str(retry_err)[:60]
        except Exception as exc:
            failed += 1
            failed_map[str(u_id)] = str(exc)[:60]
        await asyncio.sleep(0.04)
        if idx - last_progress >= 25 or idx == total:
            last_progress = idx
            try:
                await pm.edit_text(
                    f"📡 <b>Broadcasting…</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"👥 <b>Recipients:</b> <b>{total}</b>\n"
                    f"📈 <b>Progress:</b> <b>{idx}/{total}</b>\n"
                    f"📨 <b>Sent:</b> <b>{sent}</b>  ❌ <b>Failed:</b> <b>{failed}</b>",
                    parse_mode=ParseMode.HTML,
                )
            except Exception:
                pass
    broadcast_id = str(uuid.uuid4())[:8]
    try:
        save_broadcast(broadcast_id, src_preview, sent_map, failed_map if failed_map else None)
    except Exception:
        pass
    finish_kb_rows = [[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]
    if failed_map:
        finish_kb_rows.insert(0, [InlineKeyboardButton(
            f"📋 Failed List ({len(failed_map)})", callback_data=f"adm_failed_bc_{broadcast_id}"
        , style="primary")])
    try:
        await pm.edit_text(
            f"📢 <b>Broadcast Complete!</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"👥 <b>Recipients:</b> <b>{total}</b>\n"
            f"✅ <b>Sent:</b>    <b>{sent}</b>\n"
            f"❌ <b>Failed:</b>  <b>{failed}</b>\n"
            f"🚫 <b>Blocked:</b> <b>{blocked}</b>\n"
            f"🆔 <b>Broadcast ID:</b> <code>{broadcast_id}</code>",
            reply_markup=InlineKeyboardMarkup(finish_kb_rows),
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        pass
    if failed_map:
        try:
            txt_lines = [
                f"Failed Broadcast Report",
                f"Broadcast ID : {broadcast_id}",
                f"Generated    : {_now_ist():%Y-%m-%d %H:%M:%S IST}",
                f"Total Failed : {len(failed_map)}",
                "=" * 60,
                "",
            ]
            for uid_s, reason in failed_map.items():
                txt_lines.append(uid_s)
            txt_content = "\n".join(txt_lines) + "\n"
            txt_bytes   = txt_content.encode("utf-8")
            await pm._bot.send_document(
                chat_id=OWNER_ID,
                document=BytesIO(txt_bytes),
                filename="applications.txt",
                caption=(
                    f"📋 <b>Failed Broadcast Recipients</b>\n"
                    f"🆔 <code>{broadcast_id}</code>\n"
                    f"❌ <b>{len(failed_map)}</b> failed user IDs"
                ),
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass


async def cb_adm_bc_send(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("Sending…")
    if update.effective_user.id != OWNER_ID:
        return
    if get_st(ctx) != "adm_broadcast_confirm":
        clr_st(ctx)
        await q.edit_message_text("⚠️ <b>Session expired.</b>",
                                   reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML)
        return
    src_chat    = ctx.user_data.get("bc_from_chat")
    src_mid     = ctx.user_data.get("bc_msg_id")
    src_preview = ctx.user_data.get("bc_preview", "[broadcast]")
    clr_st(ctx)
    if not src_chat or not src_mid:
        await q.edit_message_text("❌ <b>Source message missing.</b>",
                                   reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML)
        return
    # Show "starting" immediately, then hand off to background task so this
    # handler returns and the admin can keep using the bot while broadcasting.
    pm = await q.edit_message_text(
        "📡 <b>Broadcasting…</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "<b>Running in background — you can still use the bot.</b>",
        parse_mode=ParseMode.HTML,
    )
    asyncio.create_task(
        _do_broadcast(ctx.bot, src_chat, src_mid, src_preview, pm)
    )


async def cb_adm_bot_broadcast(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Broadcast via hosted bot tokens to HOSTED BOT END-USERS only.

    Recipients = people who chatted with each hosted bot (stored in HOSTED_BOT_USERS_DIR).
    Hosting-bot owners / bot-uploaders in d["users"] are NOT included unless they
    also interacted with the hosted bot themselves.
    Use 📢 Broadcast (adm_broadcast) to reach hosting-bot users instead.
    """
    q = update.callback_query
    await q.answer()
    bots_list = _bb_pickable_bots()
    if not bots_list:
        await q.edit_message_text(
            "❌ <b>No hosted bots with readable tokens found.</b>\n\n"
            "<b>Start a bot that has a token in its file first.</b>",
            reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
        )
        return
    rows = []
    for entry in bots_list[:15]:
        label = f"@{entry['username']}" if entry['username'] else entry.get('name','bot')
        rows.append([InlineKeyboardButton(f"🤖 {h(label)}", callback_data=f"adm_bb_pick_{entry['bid']}", style="primary")])
    rows.append([InlineKeyboardButton("📡 All Bots", callback_data="adm_bb_pick_all", style="primary")])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")])
    await q.edit_message_text(
        "📡 <b>Bot Broadcast — Hosted Bot Users</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "<b>Select which hosted bot(s) to broadcast through:</b>\n\n"
        "<b>ℹ️ The message is sent via the hosted bot's own token.\n"
        "Only users who chatted with that hosted bot receive it.\n"
        "Hosting-bot owners / uploaders are NOT included unless they\n"
        "also interacted with the hosted bot directly.\n\n"
        "Use 📢 Broadcast to reach hosting-bot users instead.</b>",
        reply_markup=InlineKeyboardMarkup(rows),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_bb_pick(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    rest = q.data.split("adm_bb_pick_",1)[1]
    if rest == "all":
        set_st(ctx, "adm_bb_msg", bb_target="all", bb_bid="")
        desc = "all hosted bots"
    else:
        b = get_bot(rest)
        if not b:
            await q.answer("❌ Bot not found.", show_alert=True)
            return
        set_st(ctx, "adm_bb_msg", bb_target="one", bb_bid=rest)
        desc = f"<code>{h(b.get('file_name',''))}</code>"
    await q.edit_message_text(
        f"📡 <b>Bot Broadcast — {desc}</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>Send the message to broadcast.</b>\n\n"
        f"<b>Supported: text (with Premium emoji 💎), stickers, GIFs/animations,\n"
        f"photos, videos, voice messages, audio, documents.\n\n"
        f"The message will be sent via the hosted bot's token to all its known users.\n"
        f"Premium emoji and all formatting are preserved automatically.</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_del_broadcast(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    broadcasts = all_broadcasts()
    if not broadcasts:
        await q.edit_message_text(
            "🗑️ <b>Delete Broadcast</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>No broadcasts found.</b>",
            reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
        )
        return
    rows = []
    for bc in reversed(broadcasts):
        preview = bc.get("preview","")[:30]
        count   = len(bc.get("sent_map",{}))
        rows.append([InlineKeyboardButton(
            f"📢 [{bc['id']}] {bc.get('sent_at','')[:10]} — {preview}… ({count})",
            callback_data=f"adm_delbc_{bc['id']}", style="primary",
        )])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")])
    await q.edit_message_text(
        "🗑️ <b>Delete Broadcast</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>Select a broadcast to delete:</b>",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )

async def cb_adm_delbc(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    broadcast_id = q.data.split("adm_delbc_",1)[1]
    bc = get_broadcast(broadcast_id)
    if not bc:
        await q.edit_message_text("❌ <b>Broadcast not found.</b>", reply_markup=kb_back("adm_del_broadcast"), parse_mode=ParseMode.HTML)
        return
    sent_map = bc.get("sent_map",{})
    await q.edit_message_text(
        f"🗑️ <b>Confirm Delete Broadcast?</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"🆔 <b>ID:</b> <code>{broadcast_id}</code>\n"
        f"👥 <b>Sent to:</b> <b>{len(sent_map)}</b> users\n\n"
        f"<b>This will delete the broadcast from all users' chats.</b>",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Yes, Delete", callback_data=f"adm_delbc_confirm_{broadcast_id}", style="success"),
             InlineKeyboardButton("❌ Cancel",       callback_data="adm_del_broadcast", style="danger")],
        ]), parse_mode=ParseMode.HTML,
    )

async def cb_adm_delbc_confirm(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    broadcast_id = q.data.split("adm_delbc_confirm_",1)[1]
    bc = get_broadcast(broadcast_id)
    if not bc:
        await q.edit_message_text("❌ <b>Not found.</b>", reply_markup=kb_back("adm_del_broadcast"), parse_mode=ParseMode.HTML)
        return
    sent_map = bc.get("sent_map",{})
    pm = await q.edit_message_text(f"⏳ <b>Deleting from {len(sent_map)} users…</b>", parse_mode=ParseMode.HTML)
    deleted = failed = 0
    for u_id_str, msg_id in sent_map.items():
        try:
            await ctx.bot.delete_message(chat_id=int(u_id_str), message_id=msg_id)
            deleted += 1
        except Exception:
            failed += 1
    del_broadcast_record(broadcast_id)
    await pm.edit_text(
        f"🗑️ <b>Broadcast Deleted!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"✅ <b>Deleted:</b> <b>{deleted}</b>\n❌ <b>Failed:</b> <b>{failed}</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_failed_bc_list(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id != OWNER_ID:
        return
    broadcasts = all_broadcasts()
    if not broadcasts:
        await q.edit_message_text(
            "📋 <b>Failed Broadcast List</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>No broadcasts found.</b>",
            reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
        )
        return
    rows = []
    for bc in reversed(broadcasts):
        failed_map = bc.get("failed_map", {})
        if not failed_map:
            continue
        preview = bc.get("preview", "")[:25]
        rows.append([InlineKeyboardButton(
            f"📋 [{bc['id']}] {bc.get('sent_at','')[:10]} — {preview}… ❌{len(failed_map)}",
            callback_data=f"adm_failed_bc_{bc['id']}", style="primary",
        )])
    if not rows:
        await q.edit_message_text(
            "📋 <b>Failed Broadcast List</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>No broadcasts with failures found.</b>",
            reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
        )
        return
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")])
    await q.edit_message_text(
        "📋 <b>Failed Broadcast List</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "<b>Select a broadcast to see failed IDs:</b>",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )

async def cb_adm_failed_bc_detail(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id != OWNER_ID:
        return
    broadcast_id = q.data.split("adm_failed_bc_", 1)[1]
    bc = get_broadcast(broadcast_id)
    if not bc:
        await q.edit_message_text("❌ <b>Broadcast not found.</b>",
                                   reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML)
        return
    failed_map = bc.get("failed_map", {})
    if not failed_map:
        await q.edit_message_text(
            f"📋 <b>Failed List</b> — <code>{broadcast_id}</code>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"<b>No failed recipients for this broadcast.</b>",
            reply_markup=kb_back("adm_failed_bc_list"), parse_mode=ParseMode.HTML,
        )
        return
    lines = []
    for uid_s, reason in list(failed_map.items())[:50]:
        u = get_user(int(uid_s)) if uid_s.isdigit() else None
        name = ""
        uname = ""
        if u:
            name = u.get("first_name") or u.get("name") or ""
            uname = u.get("username") or ""
        tag = f"@{uname}" if uname else (f"({name})" if name else "")
        lines.append(f"• <code>{uid_s}</code> {h(tag)} — <b>{h(reason[:40])}</b>")
    extra = f"\n<b>…and {len(failed_map)-50} more</b>" if len(failed_map) > 50 else ""
    await q.edit_message_text(
        f"📋 <b>Failed List</b> — <code>{broadcast_id}</code>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"❌ <b>{len(failed_map)} failed recipients:</b>\n\n"
        + "\n".join(lines) + extra,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("📥 Download as .txt", callback_data=f"adm_failed_bc_txt_{broadcast_id}", style="primary")],
            [InlineKeyboardButton("🔙 Failed BC List", callback_data="adm_failed_bc_list", style="primary")],
            [InlineKeyboardButton("🔙 Admin Panel",    callback_data="adm_panel", style="primary")],
        ]),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_failed_bc_txt(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("📥 Generating file…")
    if update.effective_user.id != OWNER_ID:
        await q.answer("⛔ Owner only.", show_alert=True)
        return
    broadcast_id = q.data.split("adm_failed_bc_txt_", 1)[1]
    bc = get_broadcast(broadcast_id)
    if not bc:
        await q.answer("❌ Broadcast not found.", show_alert=True)
        return
    failed_map = bc.get("failed_map", {})
    if not failed_map:
        await q.answer("ℹ️ No failed recipients for this broadcast.", show_alert=True)
        return
    try:
        lines_txt = [
            f"Failed Broadcast Report",
            f"Broadcast ID : {broadcast_id}",
            f"Generated    : {_now_ist():%Y-%m-%d %H:%M:%S IST}",
            f"Total Failed : {len(failed_map)}",
            "=" * 60,
            "",
        ]
        for uid_s, reason in failed_map.items():
            u = get_user(int(uid_s)) if uid_s.isdigit() else None
            name  = ""
            uname = ""
            if u:
                name  = u.get("first_name") or u.get("name") or ""
                uname = u.get("username") or ""
            tag = f"@{uname}" if uname else (f"({name})" if name else "no info")
            lines_txt.append(f"{uid_s:<15} {tag:<25} {reason}")
        txt_content = "\n".join(lines_txt) + "\n"
        txt_bytes   = txt_content.encode("utf-8")
        fname       = f"failed_bc_{broadcast_id[:12]}.txt"
        await ctx.bot.send_document(
            chat_id=update.effective_chat.id,
            document=BytesIO(txt_bytes),
            filename=fname,
            caption=(
                f"📋 <b>Failed Broadcast Recipients</b>\n"
                f"🆔 <code>{broadcast_id}</code>\n"
                f"❌ <b>{len(failed_map)}</b> failed users"
            ),
            parse_mode=ParseMode.HTML,
        )
    except Exception as e:
        await ctx.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"❌ <b>Failed to generate file:</b> <code>{h(str(e))}</code>",
            parse_mode=ParseMode.HTML,
        )


async def cb_adm_delete_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if update.effective_user.id != OWNER_ID:
        return
    set_st(ctx, "adm_delete_users")
    await q.edit_message_text(
        "🗑️ <b>Delete Old Users</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "Send the <b>User ID(s)</b> to delete from the database.\n\n"
        "<b>Separate multiple IDs with spaces, commas, or newlines.\n"
        "You can also send a <code>.txt</code> file with one ID per line.</b>",
        reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
    )


async def cb_adm_fetch_hb_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("Fetching…")
    if update.effective_user.id != OWNER_ID:
        return
    bots_list = _bb_pickable_bots()
    if not bots_list:
        await q.edit_message_text(
            "📥 <b>Fetch Hosted Bot Users</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            "<b>No hosted bots with readable tokens found.</b>",
            reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
        )
        return
    pm = await q.edit_message_text(
        f"⏳ <b>Fetching users from {len(bots_list)} bot(s)…</b>",
        parse_mode=ParseMode.HTML,
    )
    lines = []
    total_new = 0
    for entry in bots_list:
        tok = entry["token"]
        label = f"@{entry['username']}" if entry.get("username") else entry.get("name", "bot")
        live = fetch_hosted_bot_users_from_updates(tok)
        if live:
            add_hosted_bot_users_bulk(tok, live)
            total_new += len(live)
        count = len(hosted_bot_users_list(tok))
        lines.append(f"• {h(label)} — 👥 <b>{count}</b> total (+{len(live) if live else 0} new)")
    summary = "\n".join(lines[:30])
    await pm.edit_text(
        f"📥 <b>Fetch Hosted Bot Users — Done!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"🤖 <b>Bots scanned:</b> {len(bots_list)}\n"
        f"➕ <b>New users fetched:</b> {total_new}\n\n"
        f"{summary}",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_del_custom_msg(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    msgs = all_custom_messages()
    if not msgs:
        await q.edit_message_text(
            "🗑️ <b>Delete Bot Message</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>No tracked messages found.</b>\n\n"
            "<b>You can also <b>forward</b> a bot message here to search and delete it.</b>",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📩 Forward to Delete", callback_data="adm_del_msg_fwd_mode", style="danger")],
                [InlineKeyboardButton("🔙 Admin Panel",        callback_data="adm_panel", style="primary")],
            ]),
            parse_mode=ParseMode.HTML,
        )
        return
    rows = []
    for m in reversed(msgs):
        preview = m.get("preview","")[:30]
        count   = len(m.get("chat_map",{}))
        rows.append([InlineKeyboardButton(
            f"✉️ [{m['id']}] {m.get('sent_at','')[:10]} — {preview}… ({count})",
            callback_data=f"adm_delcm_{m['id']}", style="primary",
        )])
    rows.append([InlineKeyboardButton("📩 Forward to Delete", callback_data="adm_del_msg_fwd_mode", style="danger")])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")])
    await q.edit_message_text(
        "🗑️ <b>Delete Bot Message</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "<b>Select a message to delete from all users, or forward a message to search:</b>",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )

async def cb_adm_del_msg_fwd_mode(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "adm_del_msg_fwd")
    await q.edit_message_text(
        "📩 <b>Forward Bot Message to Delete</b>\n"
        "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "<b>Forward any message that was sent by this bot.</b>\n\n"
        "<b>The bot will search all chats for matching messages and delete them.</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_del_custom_msg", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_delcm(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    msg_id = q.data.split("adm_delcm_",1)[1]
    m = get_custom_message(msg_id)
    if not m:
        await q.edit_message_text("❌ <b>Not found.</b>", reply_markup=kb_back("adm_del_custom_msg"), parse_mode=ParseMode.HTML)
        return
    chat_map = m.get("chat_map",{})
    await q.edit_message_text(
        f"🗑️ <b>Confirm Delete Message?</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"🆔 <b>ID:</b> <code>{msg_id}</code>\n"
        f"📝 <b>Preview:</b> {h(m.get('preview','')[:50])}\n"
        f"👥 <b>Sent to:</b> <b>{len(chat_map)}</b> users",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Yes, Delete", callback_data=f"adm_delcm_confirm_{msg_id}", style="success"),
             InlineKeyboardButton("❌ Cancel",       callback_data="adm_del_custom_msg", style="danger")],
        ]), parse_mode=ParseMode.HTML,
    )

async def cb_adm_delcm_confirm(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    msg_id = q.data.split("adm_delcm_confirm_",1)[1]
    record = None
    sent_map = {}
    for bc in all_broadcasts():
        if bc["id"] == msg_id:
            record = "broadcast"
            sent_map = bc.get("sent_map",{})
            break
    if not record:
        for cm in all_custom_messages():
            if cm["id"] == msg_id:
                record = "custom"
                sent_map = cm.get("chat_map",{})
                break
    if not record:
        await q.edit_message_text("❌ <b>Not found.</b>", reply_markup=kb_back("adm_del_custom_msg"), parse_mode=ParseMode.HTML)
        return
    pm = await q.edit_message_text(f"⏳ <b>Deleting from {len(sent_map)} chats…</b>", parse_mode=ParseMode.HTML)
    deleted = failed = 0
    for u_id_str, mid in sent_map.items():
        try:
            await ctx.bot.delete_message(chat_id=int(u_id_str), message_id=mid)
            deleted += 1
        except Exception:
            failed += 1
    if record == "broadcast":
        del_broadcast_record(msg_id)
    else:
        del_custom_message_record(msg_id)
    await pm.edit_text(
        f"🗑️ <b>Message Deleted!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"✅ <b>Deleted:</b> <b>{deleted}</b>\n❌ <b>Failed:</b> <b>{failed}</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_force_del(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    fwd_msg_id = q.data.split("adm_force_del_",1)[1]
    try:
        fwd_int = int(fwd_msg_id)
    except (TypeError, ValueError):
        await q.edit_message_text("❌ Invalid message ID.", reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML)
        return
    users_list = list(all_users().keys())
    pm = await q.edit_message_text(f"⏳ <b>Attempting to delete message {fwd_int} from {len(users_list)} chats…</b>", parse_mode=ParseMode.HTML)
    deleted = failed = 0
    for u_id_str in users_list:
        try:
            await ctx.bot.delete_message(chat_id=int(u_id_str), message_id=fwd_int)
            deleted += 1
        except Exception:
            failed += 1
    await pm.edit_text(
        f"🗑️ <b>Force Delete Complete</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"✅ <b>Deleted:</b> <b>{deleted}</b>\n❌ <b>Failed:</b> <b>{failed}</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_create_code(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    await q.edit_message_text(
        "💎 <b>Create Premium Code</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>Step 1:</b> Select plan:",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🍼 Baby",    callback_data="adm_cplan_baby", style="primary"),
             InlineKeyboardButton("⭐ Basic",   callback_data="adm_cplan_basic", style="primary")],
            [InlineKeyboardButton("💎 Premium", callback_data="adm_cplan_premium", style="primary"),
             InlineKeyboardButton("⚡ God",     callback_data="adm_cplan_god", style="primary")],
            [InlineKeyboardButton("👑 Ultimate",callback_data="adm_cplan_ultimate", style="primary"),
             InlineKeyboardButton("♾️ Lifetime",callback_data="adm_cplan_lifetime", style="primary")],
            [InlineKeyboardButton("❌ Cancel",   callback_data="adm_panel", style="danger")],
        ]), parse_mode=ParseMode.HTML,
    )

async def cb_adm_cplan(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    plan = q.data.split("adm_cplan_",1)[1]
    if plan not in PLANS:
        plan = "basic"
    set_st(ctx, "adm_code_days", code_plan=plan)
    pl = PLANS[plan]
    if plan == "lifetime":
        days_note = "<b>(Lifetime plans don't expire — enter any number, e.g. 36500)</b>"
    else:
        days_note = "<b>Send a number (e.g. <code>30</code>)</b>"
    await q.edit_message_text(
        f"💎 <b>Create Code — {pl['emoji']} {pl['name']}</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>Step 2:</b> How many days?\n{days_note}",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_code_do_auto(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    plan = ctx.user_data.get("code_plan","basic")
    days = ctx.user_data.get("code_days",30)
    max_uses = ctx.user_data.get("code_max_uses",1)
    if plan not in PLANS:
        plan = "basic"
    code = gen_code()
    save_code(code, plan, days, max_uses)
    clr_st(ctx)
    pl = PLANS[plan]
    duration_display = "Lifetime ♾️" if plan == "lifetime" else f"{days} days"
    await q.edit_message_text(
        f"✅ <b>Code Generated!</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"🎫 <b>Code:</b>      <code>{code}</code>\n"
        f"{pl['emoji']} <b>Plan:</b>      <b>{pl['name']}</b>\n"
        f"📅 <b>Duration:</b>  <b>{duration_display}</b>\n"
        f"👥 <b>Max Uses:</b>  <b>{max_uses}</b>\n\n"
        f"<b>Share this with your customer.</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_code_do_custom(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    plan = ctx.user_data.get("code_plan","basic")
    days = ctx.user_data.get("code_days",30)
    max_uses = ctx.user_data.get("code_max_uses",1)
    set_st(ctx, "adm_code_enter_custom", code_plan=plan, code_days=days, code_max_uses=max_uses)
    await q.edit_message_text(
        "✏️ <b>Custom Code</b>\n\nSend the custom code text:\n<b>Example: <code>MYBOT-VIP-2025</code></b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_give_sub(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "adm_givesub_uid")
    await q.edit_message_text(
        "🎁 <b>Give Subscription</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "<b>Step 1:</b> Send the <b>User ID</b>:",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_givesub_user(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid_s = q.data.split("adm_givesub_",1)[1]
    await q.edit_message_text(
        f"🎁 <b>Give Subscription</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\nUser: <code>{uid_s}</code>\n\n<b>Select plan:</b>",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🍼 Baby",    callback_data=f"adm_gsplan_baby_{uid_s}", style="primary"),
             InlineKeyboardButton("⭐ Basic",   callback_data=f"adm_gsplan_basic_{uid_s}", style="primary")],
            [InlineKeyboardButton("💎 Premium", callback_data=f"adm_gsplan_premium_{uid_s}", style="primary"),
             InlineKeyboardButton("⚡ God",     callback_data=f"adm_gsplan_god_{uid_s}", style="primary")],
            [InlineKeyboardButton("👑 Ultimate",callback_data=f"adm_gsplan_ultimate_{uid_s}", style="primary"),
             InlineKeyboardButton("♾️ Lifetime",callback_data=f"adm_gsplan_lifetime_{uid_s}", style="primary")],
            [InlineKeyboardButton("🆓 Reset Free",callback_data=f"adm_gsplan_free_{uid_s}", style="primary")],
            [InlineKeyboardButton("❌ Cancel",   callback_data=f"adm_user_{uid_s}", style="danger")],
        ]), parse_mode=ParseMode.HTML,
    )

async def cb_adm_gsplan(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    rest = q.data.split("adm_gsplan_",1)[1]
    plan, uid_s = rest.split("_",1)
    if plan not in PLANS:
        plan = "free"
    if plan == "free":
        give_subscription(int(uid_s), "free", 0)
        try:
            await ctx.bot.send_message(
                chat_id=int(uid_s),
                text="📢 <b>Plan Updated</b>\n\nYour plan has been reset to <b>🆓 Free</b> by the owner.",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
        await q.edit_message_text(
            f"✅ <b>Plan Reset</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"👤 <b>User ID:</b> <code>{uid_s}</code>\n"
            f"🆓 <b>Plan:</b> <b>Free</b>\n\n"
            f"<b>User notified.</b>",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 User Profile", callback_data=f"adm_user_{uid_s}", style="primary"),
                 InlineKeyboardButton("👥 All Users",    callback_data="adm_users", style="primary")],
            ]), parse_mode=ParseMode.HTML,
        )
        return
    if plan == "lifetime":
        # Lifetime — give directly, no need for days
        give_subscription(int(uid_s), "lifetime", 0)
        pl = PLANS["lifetime"]
        try:
            await ctx.bot.send_message(
                chat_id=int(uid_s),
                text=(
                    f"🎉 <b>Subscription Granted!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"{pl['emoji']} <b>Plan:</b>     <b>{pl['name']}</b>\n"
                    f"📅 <b>Duration:</b> <b>Lifetime ♾️ — Never expires</b>\n\n"
                    f"<b>Enjoy unlimited hosting forever! 🚀</b>"
                ),
                reply_markup=kb_main(),
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
        await q.edit_message_text(
            f"✅ <b>Subscription Granted</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"👤 <b>User ID:</b> <code>{uid_s}</code>\n"
            f"♾️ <b>Plan:</b> <b>Unlimited Lifetime</b>\n\n"
            f"<b>User notified.</b>",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 User Profile", callback_data=f"adm_user_{uid_s}", style="primary"),
                 InlineKeyboardButton("👥 All Users",    callback_data="adm_users", style="primary")],
            ]), parse_mode=ParseMode.HTML,
        )
        return
    pl = PLANS[plan]
    set_st(ctx, "adm_gsub_days", gs_plan=plan, gs_uid=uid_s)
    await q.edit_message_text(
        f"🎁 <b>Give Sub — {pl['emoji']} {pl['name']}</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"User: <code>{uid_s}</code>\n\n<b>How many days?</b>\n<b>Send a number (e.g. <code>30</code>)</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data=f"adm_user_{uid_s}", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_custom_ram(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "adm_customram_uid")
    await q.edit_message_text(
        "🧠 <b>Custom RAM Allowance</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "Assign a custom per-bot RAM limit to any user, overriding their plan's default (works on Free too).\n\n"
        "<b>Step 1:</b> Send the <b>User ID</b>:",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_customram_set(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    # Shortcut from a User Profile card — target is already known, so skip
    # straight to step 2 (asking only for the RAM amount).
    q = update.callback_query
    await q.answer()
    uid_s = q.data.split("adm_customram_set_",1)[1]
    target_uid = int(uid_s)
    u = get_user(target_uid)
    if not u:
        await q.edit_message_text("❌ User not found.", reply_markup=kb_back("adm_users_menu"), parse_mode=ParseMode.HTML)
        return
    current_plan = PLANS.get(u.get("plan","free"), PLANS["free"])
    current_custom = u.get("custom_ram_mb")
    current_str = f"{current_custom} MB (custom)" if current_custom else f"{current_plan.get('ram_mb','?')} MB (plan default)"
    set_st(ctx, "adm_customram_value", cram_uid=target_uid)
    await q.edit_message_text(
        f"🧠 <b>Custom RAM Allowance</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"User: <code>{target_uid}</code> ({h(user_display(uid_s, u))})\n"
        f"Plan: {current_plan.get('emoji','')} {current_plan.get('name','Free')}\n"
        f"Current RAM: <b>{current_str}</b>\n\n"
        f"<b>Send the new RAM limit for this user</b>\n"
        f"<b>e.g.</b> <code>512mb</code>, <code>2gb</code>, or a plain number in MB like <code>768</code>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data=f"adm_user_{uid_s}", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_customram_revoke(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    uid_s = q.data.split("adm_customram_revoke_",1)[1]
    target_uid = int(uid_s)
    u = get_user(target_uid)
    if not u:
        await q.answer()
        await q.edit_message_text("❌ User not found.", reply_markup=kb_back("adm_users_menu"), parse_mode=ParseMode.HTML)
        return
    if u.get("custom_ram_mb") is None:
        await q.answer("This user has no custom RAM set.", show_alert=True)
        return
    await q.answer("Custom RAM revoked ✅")
    upd_user(target_uid, {"custom_ram_mb": None})
    try:
        await ctx.bot.send_message(
            chat_id=target_uid,
            text=(
                "📢 <b>RAM Allowance Updated</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                "Your custom RAM override has been <b>revoked</b>.\n"
                "<b>You're now back on your plan's default RAM limit.</b>"
            ),
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        pass
    await _render_adm_user_det(q, uid_s)

async def cb_adm_files_pick(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    page = 0
    if q.data.startswith("adm_files_page_"):
        try:
            page = int(q.data.split("adm_files_page_", 1)[1])
        except ValueError:
            page = 0
    PAGE_SIZE = 20
    all_items = [(uid, u) for uid, u in all_users().items() if len(u.get("bots",[])) > 0]
    if not all_items:
        await q.edit_message_text("📂 <b>No files uploaded yet.</b>", reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML)
        return
    total_pages = max(1, (len(all_items) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, total_pages - 1))
    slice_ = all_items[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]
    rows = []
    for uid, u in slice_:
        fc = len(u.get("bots",[]))
        rows.append([InlineKeyboardButton(f"📂 {h(user_display(uid, u))} ({fc})", callback_data=f"adm_ufiles_{uid}", style="primary")])
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("◀️ Prev", callback_data=f"adm_files_page_{page-1}", style="primary"))
    if page < total_pages - 1:
        nav.append(InlineKeyboardButton("Next ▶️", callback_data=f"adm_files_page_{page+1}", style="primary"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")])
    await q.edit_message_text(
        f"📂 <b>User Files</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>{len(all_items)}</b> user(s) with files  |  Page <b>{page+1}</b>/<b>{total_pages}</b>\n\nSelect a user:",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML)

async def cb_adm_ufiles(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    sync_statuses()
    uid_s = q.data.split("adm_ufiles_",1)[1]
    bots  = user_bots(int(uid_s))
    msg = q.message
    # Detect whether the source message contains media (document, photo, etc.)
    # edit_message_text fails on media messages — send a new message instead.
    _has_media = bool(
        getattr(msg, "document", None) or
        getattr(msg, "photo", None) or
        getattr(msg, "video", None) or
        getattr(msg, "audio", None)
    )
    if not bots:
        text = f"📂 No files for <code>{uid_s}</code>."
        kb   = kb_back("adm_files_pick")
        if _has_media:
            await msg.reply_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)
        else:
            await q.edit_message_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)
        return
    rows = []
    for b in bots:
        label = f"⏳ {h(b['file_name'])} [Pending]" if b.get("pending") else f"{si(b['status'])} {h(b['file_name'])}"
        rows.append([InlineKeyboardButton(label, callback_data=f"adm_fdet_{uid_s}_{b['bot_id']}", style="primary")])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_files_pick", style="primary")])
    run = sum(1 for b in bots if b.get("status") == "running")
    text = (
        f"📂 <b>Files — <code>{uid_s}</code></b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"📁 Total: <b>{len(bots)}</b>  •  🟢 Running: <b>{run}</b>"
    )
    kb = InlineKeyboardMarkup(rows)
    if _has_media:
        await msg.reply_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)
    else:
        await q.edit_message_text(text, reply_markup=kb, parse_mode=ParseMode.HTML)

async def cb_adm_fdet(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    clr_st(ctx)   # cancel any pending reject-reason (or similar) prompt tied to this screen
    rest  = q.data.split("adm_fdet_",1)[1]
    uid_s, bid = rest.split("_",1)
    is_media_msg = bool(q.message and q.message.document)

    async def _render(txt: str, markup):
        """Edit caption if this is a media/document message, else edit text.
        Editing text on a caption-only message (or vice versa) is silently
        rejected by Telegram, which is why Cancel used to do nothing."""
        if is_media_msg:
            try:
                await q.edit_message_caption(txt, reply_markup=markup, parse_mode=ParseMode.HTML)
                return
            except Exception:
                pass
        try:
            await q.edit_message_text(txt, reply_markup=markup, parse_mode=ParseMode.HTML)
        except Exception:
            await ctx.bot.send_message(chat_id=q.message.chat_id, text=txt, reply_markup=markup, parse_mode=ParseMode.HTML)

    b = get_bot(bid)
    if not b:
        await _render("❌ Not found.", kb_back(f"adm_ufiles_{uid_s}"))
        return
    s   = b.get("status","stopped")
    pid = b.get("pid")
    pending = b.get("pending", False)
    proj = b.get("project_name","").strip()
    ipid = b.get("internal_pid")
    text = (
        f"📁 <b>File Details</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        + (f"🔢 <b>Bot #:</b>   <code>{ipid}</code>\n" if ipid else "")
        + f"📄 <b>Name:</b>   <code>{h(b['file_name'])}</code>\n"
        + (f"📁 <b>Project:</b> <code>{h(proj)}</code>\n" if proj else "")
        + f"👤 <b>User:</b>   <code>{uid_s}</code>\n"
        f"📊 <b>Status:</b> {'⏳ <b>Pending Approval</b>' if pending else si(s)}\n"
    )
    if s == "running" and not pending and pid and _alive(pid):
        text += f"⏱️ <b>Uptime:</b> <code>{h(bot_uptime(b))}</code>\n"
    if pending:
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Approve", callback_data=f"adm_approve_{uid_s}_{bid}", style="success"),
             InlineKeyboardButton("❌ Reject",  callback_data=f"adm_reject_{uid_s}_{bid}", style="danger")],
            [InlineKeyboardButton("🔙 Back",    callback_data=f"adm_ufiles_{uid_s}", style="primary")],
        ])
    else:
        run_btn = (
            InlineKeyboardButton("❌ Stop", callback_data=f"adm_fact_stop_{uid_s}_{bid}", style="danger")
            if s == "running" else
            InlineKeyboardButton("▶️ Run",  callback_data=f"adm_fact_start_{uid_s}_{bid}", style="success")
        )
        kb = InlineKeyboardMarkup([
            [run_btn,
             InlineKeyboardButton("🔄 Restart", callback_data=f"adm_fact_restart_{uid_s}_{bid}", style="primary")],
            [InlineKeyboardButton("📋 Logs",  callback_data=f"adm_fact_logs_{uid_s}_{bid}", style="primary"),
             InlineKeyboardButton("💾 Save",  callback_data=f"adm_fact_save_{uid_s}_{bid}", style="success")],
            [InlineKeyboardButton("🔁 Replace File", callback_data=f"adm_replace_pick_{bid}", style="primary"),
             InlineKeyboardButton("👤 Transfer", callback_data=f"adm_fact_transfer_{uid_s}_{bid}", style="primary")],
            [InlineKeyboardButton("🗑️ Delete", callback_data=f"adm_fact_delete_{uid_s}_{bid}", style="danger")],
            [InlineKeyboardButton("🔙 Back",   callback_data=f"adm_ufiles_{uid_s}", style="primary")],
        ])
    await _render(text, kb)


async def cb_adm_fact(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    rest          = q.data.split("adm_fact_",1)[1]
    action, rest2 = rest.split("_",1)
    uid_s, bid    = rest2.split("_",1)
    b = get_bot(bid)
    if not b:
        await q.edit_message_text("❌ Not found.", reply_markup=kb_back(f"adm_ufiles_{uid_s}"))
        return
    if action == "logs":
        logs_md = format_logs_md2(bid)
        await q.edit_message_text(
            logs_md,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄 Refresh", callback_data=f"adm_fact_logs_{uid_s}_{bid}", style="primary"),
                 InlineKeyboardButton("🔙 Back",    callback_data=f"adm_fdet_{uid_s}_{bid}", style="primary")],
            ]),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return
    if action == "transfer":
        set_st(ctx, "adm_transfer_bot", transfer_bid=bid)
        await q.edit_message_text(
            f"👤 <b>Transfer Bot Ownership</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📄 <b>Bot:</b> <code>{h(b.get('file_name',''))}</code>\n"
            f"👤 <b>Current Owner:</b> <code>{uid_s}</code>\n\n"
            f"<b>Send the User ID of the new owner.</b>",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data=f"adm_fdet_{uid_s}_{bid}", style="danger")]]),
            parse_mode=ParseMode.HTML,
        )
        return
    if action in ("start","stop","restart"):
        if action == "start":     _, msg = await asyncio.get_running_loop().run_in_executor(None, proc_start, bid)
        elif action == "stop":    _, msg = proc_stop(bid)
        else:                     _, msg = await asyncio.get_running_loop().run_in_executor(None, proc_restart, bid)
        await q.edit_message_text(
            msg,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data=f"adm_fdet_{uid_s}_{bid}", style="primary")]]),
            parse_mode=ParseMode.HTML,
        )
    elif action == "delete":
        proc_stop(bid)
        remove_bot_file(b)
        del_bot(bid)
        await q.edit_message_text(
            f"🗑️ <b>File Deleted</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📄 <b>File:</b> <code>{h(b['file_name'])}</code>\n"
            f"👤 <b>User ID:</b> <code>{uid_s}</code>\n\n"
            f"<b>Removed successfully.</b>",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 User Files", callback_data=f"adm_ufiles_{uid_s}", style="primary")]]),
            parse_mode=ParseMode.HTML,
        )
    elif action == "save":
        send_fp = get_sendable_file_path(b)
        if not send_fp:
            await q.edit_message_text("❌ File not found on disk.", reply_markup=kb_back(f"adm_fdet_{uid_s}_{bid}"))
            return
        stored_fp = b.get("file_path","")
        _tmp_created = (send_fp != stored_fp and send_fp and os.path.exists(send_fp))
        bk = os.path.join(BACKUP_DIR, uid_s)
        os.makedirs(bk, exist_ok=True)
        try:
            shutil.copy2(send_fp, os.path.join(bk, b["file_name"]))
        except Exception:
            pass
        try:
            with open(send_fp,"rb") as f:
                await ctx.bot.send_document(
                    chat_id=OWNER_ID, document=f, filename=b["file_name"],
                    caption=f"💾 <b>Saved File</b>\n👤 <code>{uid_s}</code>\n📄 <code>{h(b['file_name'])}</code>",
                    parse_mode=ParseMode.HTML,
                )
            await q.answer("✅ File sent!", show_alert=True)
        except Exception as e:
            await q.answer(f"❌ {e}", show_alert=True)
        finally:
            if _tmp_created and os.path.exists(send_fp):
                try:
                    os.remove(send_fp)
                except Exception:
                    pass


async def cb_adm_approve(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    rest = q.data.split("adm_approve_",1)[1]
    uid_s, bid = rest.split("_",1)
    b = get_bot(bid)
    if not b:
        deleted_msg = (
            "🗑️ <b>Bot Deleted by User</b>\n"
            "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"🆔 <b>Bot ID:</b> <code>{bid}</code>\n"
            f"👤 <b>User ID:</b> <code>{uid_s}</code>\n\n"
            "<b>The user deleted this bot before you approved it.\n"
            "No action needed.</b>"
        )
        result_kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]])
        is_media_msg = bool(q.message and q.message.document)
        if is_media_msg:
            try:
                await q.edit_message_caption(deleted_msg, reply_markup=result_kb, parse_mode=ParseMode.HTML)
            except Exception:
                await ctx.bot.send_message(chat_id=OWNER_ID, text=deleted_msg, reply_markup=result_kb, parse_mode=ParseMode.HTML)
        else:
            try:
                await q.edit_message_text(deleted_msg, reply_markup=result_kb, parse_mode=ParseMode.HTML)
            except Exception:
                await ctx.bot.send_message(chat_id=OWNER_ID, text=deleted_msg, reply_markup=result_kb, parse_mode=ParseMode.HTML)
        return
    upd_bot(bid, {"pending": False})
    approved_ext = file_ext(b.get("file_name", ""))
    is_runnable_file = approved_ext == ".py"
    is_media_msg = bool(q.message and q.message.document)
    if is_runnable_file:
        installing_msg = (
            "<b>✅ Approved Installing modules\n"
            "🚀 Starting bot shortly....</b>"
        )
        try:
            if is_media_msg:
                await q.edit_message_caption(installing_msg, parse_mode=ParseMode.HTML)
            else:
                await q.edit_message_text(installing_msg, parse_mode=ParseMode.HTML)
        except Exception:
            pass
        ok, msg = await asyncio.get_running_loop().run_in_executor(None, proc_start, bid)
        user_notify = (
            f"✅ <b>Bot Approved!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📄 <b>File:</b> <code>{h(b['file_name'])}</code>\n\n"
            f"{'🟢 <b>Your bot is now running!</b>' if ok else '⚠️ <b>Approved but failed to start:</b> ' + msg}\n\n"
            f"<b>Manage your bot from My Bots.</b>"
        )
        owner_rec = get_user(int(uid_s))
        owner_uname = (owner_rec or {}).get("username")
        owner_dispname = (owner_rec or {}).get("first_name") or f"User {uid_s}"
        owner_display = f"@{owner_uname}" if owner_uname else owner_dispname
        owner_line = f'\n👤 <b>Owner:</b> <a href="tg://openmessage?user_id={uid_s}">{h(owner_display)}</a>'
        if ok:
            tok_for_lookup = get_decrypted_bot_token(b) or extract_bot_token(b.get("file_path", ""))
            approved_username = await auto_fetch_bot_username(tok_for_lookup)
            username_suffix = f"\n💌 <b>Bot Username:</b> @{h(approved_username)}" if approved_username else ""
            status_msg = f"✅ <b>Approved &amp; Started!</b>{username_suffix}{owner_line}"
        else:
            status_msg = f"✅ <b>Approved.</b> Start failed: {msg}{owner_line}"
    else:
        ok = True
        user_notify = (
            f"✅ <b>File Approved!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📄 <b>File:</b> <code>{h(b['file_name'])}</code>\n\n"
            f"💾 <b>Your file has been saved and is ready to use.</b>\n\n"
            f"<b>Manage your files from My Bots.</b>"
        )
        owner_rec = get_user(int(uid_s))
        owner_uname = (owner_rec or {}).get("username")
        owner_dispname = (owner_rec or {}).get("first_name") or f"User {uid_s}"
        owner_display = f"@{owner_uname}" if owner_uname else owner_dispname
        owner_line = f'\n👤 <b>Owner:</b> <a href="tg://openmessage?user_id={uid_s}">{h(owner_display)}</a>'
        status_msg = f"✅ <b>Approved &amp; Saved!</b> (<code>{h(b['file_name'])}</code>){owner_line}"
    try:
        await ctx.bot.send_message(
            chat_id=int(uid_s),
            text=user_notify,
            reply_markup=kb_main(),
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        pass
    result_kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_bot_mgmt", style="primary")]])
    if is_media_msg:
        try:
            await q.edit_message_caption(status_msg, reply_markup=result_kb, parse_mode=ParseMode.HTML)
        except Exception:
            await ctx.bot.send_message(chat_id=OWNER_ID, text=status_msg, reply_markup=result_kb, parse_mode=ParseMode.HTML)
    else:
        try:
            await q.edit_message_text(status_msg, reply_markup=result_kb, parse_mode=ParseMode.HTML)
        except Exception:
            await ctx.bot.send_message(chat_id=OWNER_ID, text=status_msg, reply_markup=result_kb, parse_mode=ParseMode.HTML)

async def cb_adm_reject(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    rest = q.data.split("adm_reject_",1)[1]
    uid_s, bid = rest.split("_",1)
    # Check if bot still exists before asking for a reason
    b = get_bot(bid)
    if not b:
        deleted_msg = (
            "🗑️ <b>Bot Deleted by User</b>\n"
            "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"🆔 <b>Bot ID:</b> <code>{bid}</code>\n"
            f"👤 <b>User ID:</b> <code>{uid_s}</code>\n\n"
            "<b>The user deleted this bot before you rejected it.\n"
            "No action needed.</b>"
        )
        result_kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]])
        is_media_msg = bool(q.message and q.message.document)
        if is_media_msg:
            try:
                await q.edit_message_caption(deleted_msg, reply_markup=result_kb, parse_mode=ParseMode.HTML)
            except Exception:
                await ctx.bot.send_message(chat_id=OWNER_ID, text=deleted_msg, reply_markup=result_kb, parse_mode=ParseMode.HTML)
        else:
            try:
                await q.edit_message_text(deleted_msg, reply_markup=result_kb, parse_mode=ParseMode.HTML)
            except Exception:
                await ctx.bot.send_message(chat_id=OWNER_ID, text=deleted_msg, reply_markup=result_kb, parse_mode=ParseMode.HTML)
        return
    set_st(ctx, "adm_reject_reason", reject_uid=uid_s, reject_bid=bid,
           reject_msg_id=q.message.message_id, reject_chat_id=q.message.chat_id)
    is_media_msg = bool(q.message and q.message.document)
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("⏭ Skip Reason", callback_data=f"adm_reject_no_reason_{uid_s}_{bid}", style="danger")],
        [InlineKeyboardButton("❌ Cancel",       callback_data=f"adm_fdet_{uid_s}_{bid}", style="danger")],
    ])
    if is_media_msg:
        try:
            await q.edit_message_caption(
                "❌ <b>Reject Bot</b>\n\nSend the reason for rejection, or tap Skip Reason.",
                reply_markup=kb, parse_mode=ParseMode.HTML,
            )
        except Exception:
            await ctx.bot.send_message(chat_id=OWNER_ID, text="❌ <b>Reject Bot</b>\n\nSend the reason:", reply_markup=kb, parse_mode=ParseMode.HTML)
    else:
        await q.edit_message_text(
            "❌ <b>Reject Bot</b>\n\nSend the reason for rejection, or tap Skip Reason.",
            reply_markup=kb, parse_mode=ParseMode.HTML,
        )

async def finalize_admin_rejection(ctx, uid_s: str, bid: str, reason: str = "") -> str:
    b = get_bot(bid)
    if not b:
        return (
            "🗑️ <b>Bot Deleted by User</b>\n"
            "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"🆔 <b>Bot ID:</b> <code>{bid}</code>\n"
            f"👤 <b>User ID:</b> <code>{uid_s}</code>\n\n"
            "<b>The user already deleted this bot.\n"
            "No action needed.</b>"
        )
    bot_username = await auto_fetch_bot_username(
        get_decrypted_bot_token(b) or extract_bot_token(b.get("file_path",""))
    )
    proc_stop(bid)
    remove_bot_file(b)
    del_bot(bid)
    reason_block = f"\n\n📝 <b>Reason:</b>\n{quote_block(reason)}" if reason else "\n"
    try:
        await ctx.bot.send_message(
            chat_id=int(uid_s),
            text=(
                f"❌ <b>Bot Rejected</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"📄 <b>File:</b> <code>{h(b['file_name'])}</code>\n\n"
                f"<b>Your bot was rejected by the owner.</b>"
                f"{reason_block}\n"
                f"<b>Contact @{DEVELOPER_USERNAME} for more info.</b>"
            ),
            reply_markup=kb_main(),
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        pass
    username_block = f"\n🤖 <b>Bot Username:</b> @{h(bot_username)}" if bot_username else ""
    return (
        f"❌ <b>Bot Rejected & Deleted</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"📄 <b>File:</b> <code>{h(b['file_name'])}</code>\n"
        f"👤 <b>User ID:</b> <code>{uid_s}</code>"
        f"{username_block}\n\n"
        f"📝 <b>Reason:</b>\n{quote_block(reason)}\n"
        f"<b>File deleted and user notified.</b>"
    )

async def cb_adm_reject_no_reason(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    rest = q.data.split("adm_reject_no_reason_",1)[1]
    uid_s, bid = rest.split("_",1)
    clr_st(ctx)
    result_text = await finalize_admin_rejection(ctx, uid_s, bid)
    result_kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]])
    is_media_msg = bool(q.message and q.message.document)
    if is_media_msg:
        try:
            await q.edit_message_caption(result_text, reply_markup=result_kb, parse_mode=ParseMode.HTML)
        except Exception:
            await ctx.bot.send_message(chat_id=OWNER_ID, text=result_text, reply_markup=result_kb, parse_mode=ParseMode.HTML)
    else:
        try:
            await q.edit_message_text(result_text, reply_markup=result_kb, parse_mode=ParseMode.HTML)
        except Exception:
            await ctx.bot.send_message(chat_id=OWNER_ID, text=result_text, reply_markup=result_kb, parse_mode=ParseMode.HTML)


async def cb_adm_set_qr(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "adm_set_qr_img")
    current      = get_setting("payment_qr", "")
    local_ok     = bool(current and os.path.exists(current))
    backup_msg_id = get_setting("qr_backup_msg_id", "")
    has_backup   = bool(backup_msg_id)
    status_line  = "✅ Set (local file OK)" if local_ok else ("❌ Missing locally" + (" — ☁️ backup available" if has_backup else ""))
    kb_rows = []
    if not local_ok and has_backup:
        kb_rows.append([InlineKeyboardButton("☁️ Restore QR from Backup", callback_data="adm_restore_qr", style="success")])
    kb_rows.append([InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")])
    await q.edit_message_text(
        f"🖼 <b>Set Payment QR Code</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>Current QR:</b> {status_line}\n\n"
        f"<b>Send a photo</b> of your QR code to update it.",
        reply_markup=InlineKeyboardMarkup(kb_rows),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_restore_qr(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("☁️ Restoring QR from backup…")
    if update.effective_user.id != OWNER_ID:
        await q.answer("⛔ Owner only.", show_alert=True)
        return
    backup_msg_id = get_setting("qr_backup_msg_id", "")
    if not backup_msg_id:
        await q.edit_message_text("❌ <b>No backup QR found in cloud channel.</b>",
                                   reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML)
        return
    try:
        msg = await ctx.bot.forward_message(
            chat_id=update.effective_chat.id,
            from_chat_id=CLOUD_STORAGE_CHAT_ID,
            message_id=int(backup_msg_id),
        )
        # Download the forwarded photo and save locally
        if msg.photo:
            best = max(msg.photo, key=lambda p: p.file_size)
            tg_file = await ctx.bot.get_file(best.file_id)
            qr_path = os.path.join(BASE_DIR, "payment_qr.jpg")
            await tg_file.download_to_drive(qr_path)
            upd_settings({"payment_qr": qr_path})
            try:
                await ctx.bot.delete_message(chat_id=update.effective_chat.id, message_id=msg.message_id)
            except Exception:
                pass
            await q.edit_message_text(
                "✅ <b>Payment QR restored from cloud backup!</b>",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
                parse_mode=ParseMode.HTML,
            )
        else:
            await q.edit_message_text("❌ <b>Backup message has no photo.</b>",
                                       reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML)
    except Exception as e:
        await q.edit_message_text(
            f"❌ <b>Restore failed:</b> <code>{h(str(e))}</code>",
            reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
        )


async def cb_adm_set_upi(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "adm_set_upi")
    current = get_setting("payment_upi","").strip()
    await q.edit_message_text(
        f"💳 <b>Set UPI ID</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>Current UPI:</b> {('<code>' + h(current) + '</code>') if current else '❌ Not set'}\n\n"
        f"<b>Send your UPI ID</b> to update it.\n<b>Example: <code>yourname@upi</code></b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_set_custom_uptime(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "adm_set_custom_uptime")
    current = get_setting("custom_uptime","").strip()
    await q.edit_message_text(
        f"⏱️ <b>Set Custom Uptime Message</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"<b>Current:</b> {('<code>' + h(current) + '</code>') if current else '❌ Not set'}\n\n"
        f"<b>Send a custom value</b> to replace the <b>Main bot uptime</b> "
        f"shown to users on their Bot Uptime page.\n\n"
        f"<b>Example:</b> <code>99.9% uptime — Server: Mumbai 🇮🇳</code>\n\n"
        f"<b>Send <code>clear</code> to go back to showing the real uptime.</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_payments(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    pending_pays = all_payment_pending()
    if not pending_pays:
        await q.edit_message_text(
            "💳 <b>Pending Payments</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>No pending payment verifications.</b>",
            reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
        )
        return
    rows = []
    for uid_s, pay in list(pending_pays.items())[:20]:
        u = get_user(int(uid_s))
        plan = pay.get("plan","?")
        pl = PLANS.get(plan, {})
        rows.append([InlineKeyboardButton(
            f"💳 {h(user_display(uid_s,u))} — {pl.get('name',plan)}",
            callback_data=f"adm_pay_view_{uid_s}", style="primary",
        )])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")])
    await q.edit_message_text(
        f"💳 <b>Pending Payments</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>{len(pending_pays)}</b> pending:",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )

async def cb_adm_pay_view(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid_s = q.data.split("adm_pay_view_",1)[1]
    pay = get_payment_pending(int(uid_s))
    if not pay:
        await q.edit_message_text("❌ Payment not found.", reply_markup=kb_back("adm_payments"), parse_mode=ParseMode.HTML)
        return
    plan = pay.get("plan","?")
    pl = PLANS.get(plan, {})
    u = get_user(int(uid_s))
    await q.edit_message_text(
        f"💳 <b>Payment Review</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"👤 <b>User:</b> {h(user_display(uid_s,u))}\n"
        f"🆔 <b>ID:</b> <code>{uid_s}</code>\n"
        f"💰 <b>Plan:</b> {pl.get('emoji','')} <b>{pl.get('name',plan)}</b> — {pl.get('price','?')}\n\n"
        f"<b>Forward the payment screenshot to see it, then verify or deny.</b>",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Verify",   callback_data=f"adm_pay_verify_{uid_s}", style="success"),
             InlineKeyboardButton("❌ Deny",     callback_data=f"adm_pay_deny_{uid_s}", style="danger")],
            [InlineKeyboardButton("🔙 Payments", callback_data="adm_payments", style="primary")],
        ]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_pay_verify(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid_s = q.data.split("adm_pay_verify_",1)[1]
    pay = get_payment_pending(int(uid_s))
    if not pay:
        await q.edit_message_text("❌ Payment not found.", reply_markup=kb_back("adm_payments"), parse_mode=ParseMode.HTML)
        return
    plan = pay.get("plan","baby")
    if plan not in PLANS:
        plan = "baby"
    pl = PLANS[plan]
    # Lifetime gets no expiry; others get 30 days
    if plan == "lifetime":
        give_subscription(int(uid_s), plan, 0)
        duration_msg = "Lifetime ♾️ — Never expires"
    else:
        give_subscription(int(uid_s), plan, 30)
        duration_msg = "30 days"
    del_payment_pending(int(uid_s))
    try:
        await ctx.bot.send_message(
            chat_id=int(uid_s),
            text=(
                f"✅ <b>Payment Verified!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"{pl['emoji']} <b>Plan:</b> <b>{pl['name']}</b>\n"
                f"📅 <b>Duration:</b> <b>{duration_msg}</b>\n\n"
                f"<b>🎉 Welcome to your new plan! Enjoy premium hosting!</b>"
            ),
            reply_markup=kb_main(),
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        pass
    await q.edit_message_text(
        f"✅ <b>Payment Verified</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"👤 <b>User ID:</b> <code>{uid_s}</code>\n"
        f"{pl['emoji']} <b>Plan:</b> <b>{pl['name']}</b>\n"
        f"📅 <b>Duration:</b> {duration_msg}\n\n"
        f"<b>User notified and upgraded.</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Payments", callback_data="adm_payments", style="primary")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_pay_deny(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    uid_s = q.data.split("adm_pay_deny_",1)[1]
    set_st(ctx, "adm_pay_deny_reason", deny_uid=uid_s)
    await q.edit_message_text(
        "❌ <b>Deny Payment</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\nSend the reason for denial:",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data=f"adm_pay_view_{uid_s}", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_replace_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    bots_db = all_bots()
    if not bots_db:
        await q.edit_message_text("❌ <b>No bots found.</b>", reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML)
        return
    rows = []
    for bid, b in list(bots_db.items())[:20]:
        uid_s = str(b.get("user_id",""))
        u = get_user(int(uid_s)) if uid_s else None
        rows.append([InlineKeyboardButton(
            f"🔄 {h(b['file_name'])} ({h(user_display(uid_s,u))})",
            callback_data=f"adm_replace_pick_{bid}", style="primary",
        )])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")])
    await q.edit_message_text(
        "🔄 <b>Replace File System</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "<b>Select the bot file to replace:</b>",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )

async def cb_adm_replace_pick(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    bid = q.data.split("adm_replace_pick_",1)[1]
    b = get_bot(bid)
    if not b:
        await q.answer("❌ Not found.", show_alert=True)
        return
    set_st(ctx, "adm_replace_file_upload", replace_bid=bid)
    await q.edit_message_text(
        f"🔄 <b>Replace File</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"📄 <b>Current:</b> <code>{h(b['file_name'])}</code>\n\n"
        f"<b>Send the new file now.</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_replace_file", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )

async def cb_adm_save_file_pick(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    bots_db = all_bots()
    if not bots_db:
        await q.edit_message_text("❌ <b>No bots found.</b>", reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML)
        return
    rows = []
    for bid, b in list(bots_db.items())[:20]:
        uid_s = str(b.get("user_id",""))
        u = get_user(int(uid_s)) if uid_s else None
        rows.append([InlineKeyboardButton(
            f"💾 {h(b['file_name'])} ({h(user_display(uid_s,u))})",
            callback_data=f"adm_fact_save_{uid_s}_{bid}", style="success",
        )])
    rows.append([InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")])
    await q.edit_message_text(
        "💾 <b>Save File</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>Select file to save to your DM:</b>",
        reply_markup=InlineKeyboardMarkup(rows), parse_mode=ParseMode.HTML,
    )


async def cb_adm_github_import(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "adm_github_url")
    await q.edit_message_text(
        "📥 <b>GitHub Import</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "<b>Send the raw GitHub file URL to import:</b>\n\n"
        "<b>Example:\n"
        "<code>https://raw.githubusercontent.com/user/repo/main/bot.py</code></b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )


async def cb_adm_add_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    set_st(ctx, "adm_add_users")
    await q.edit_message_text(
        "➕ <b>Add Old Users</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "<b>Send user IDs or upload a .txt file.</b>\n\n"
        "<b>Accepted formats:</b>\n"
        "• Multiple IDs: <code>123456 789012 345678</code>\n"
        "• One per line\n"
        "• <b>.txt file</b> with IDs (one per line)\n\n"
        "<b>The bot will fetch name, username, and register them.</b>",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
        parse_mode=ParseMode.HTML,
    )


# Regex patterns to extract Telegram user IDs from any text source
_UID_PATTERNS = [
    re.compile(r'(?:user_id|chat_id|from_user\.id|user\.id|sender_id|from_id)["\s:=]+(\d{5,12})'),
    re.compile(r'(?:Chat|User|Sender|From)\s*\(?id\s*[=:]\s*(\d{5,12})'),
    re.compile(r'"id"\s*:\s*(\d{5,12})'),
    re.compile(r"'id'\s*:\s*(\d{5,12})"),
    re.compile(r'\bid\s*[=:]\s*(\d{5,12})\b'),
    re.compile(r'(?:^|[\s,\[{(])(\d{8,12})(?:[\s,\]})"]|$)'),  # bare 8-12 digit numbers
]

def _is_valid_uid(n: int) -> bool:
    return 10_000 <= n <= 9_999_999_999

def _extract_uids_from_text(text: str) -> set:
    found = set()
    for pat in _UID_PATTERNS:
        for m in pat.finditer(text):
            try:
                uid = int(m.group(1))
                if _is_valid_uid(uid):
                    found.add(uid)
            except (ValueError, IndexError):
                pass
    return found

def _scrape_ids_from_log(log_path: str) -> set:
    found = set()
    if not log_path or not os.path.exists(log_path):
        return found
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                found.update(_extract_uids_from_text(line))
    except Exception:
        pass
    return found

def _scrape_ids_from_json_file(fpath: str) -> set:
    found = set()
    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read(2_000_000)  # cap at 2 MB
        data = json.loads(raw)
    except Exception:
        # Not valid JSON — try extracting IDs as plain text
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read(2_000_000)
            found.update(_extract_uids_from_text(raw))
        except Exception:
            pass
        return found

    def _walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                # Keys that are numeric strings (e.g. {"123456789": {...}})
                try:
                    uid = int(k)
                    if _is_valid_uid(uid):
                        found.add(uid)
                except (ValueError, TypeError):
                    pass
                # Check values named like user_id, chat_id, id, etc.
                if isinstance(k, str) and k.lower() in (
                    "id", "user_id", "chat_id", "from_id", "sender_id",
                    "userid", "chatid", "uid"
                ):
                    try:
                        uid = int(v)
                        if _is_valid_uid(uid):
                            found.add(uid)
                    except (ValueError, TypeError):
                        pass
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)
        elif isinstance(obj, (int, float)):
            try:
                uid = int(obj)
                if _is_valid_uid(uid):
                    found.add(uid)
            except (ValueError, TypeError):
                pass

    _walk(data)
    return found

def _scrape_ids_from_sqlite(fpath: str) -> set:
    found = set()
    try:
        import sqlite3
        conn = sqlite3.connect(fpath)
        cur  = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        for table in tables:
            try:
                cur.execute(f'SELECT * FROM "{table}" LIMIT 5000')
                cols = [d[0].lower() for d in cur.description]
                for row in cur.fetchall():
                    for col_idx, col_name in enumerate(cols):
                        if any(kw in col_name for kw in ("id", "user", "chat", "uid", "sender")):
                            try:
                                uid = int(row[col_idx])
                                if _is_valid_uid(uid):
                                    found.add(uid)
                            except (TypeError, ValueError, IndexError):
                                pass
            except Exception:
                pass
        conn.close()
    except Exception:
        pass
    return found

def _scrape_ids_from_txt(fpath: str) -> set:
    found = set()
    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                found.update(_extract_uids_from_text(line))
    except Exception:
        pass
    return found

def _collect_ids_from_bot_folder(bot_dir: str) -> set:
    """
    Walk the bot's folder and try to extract user IDs from every data file:
      • .json  — parsed as JSON or plain text
      • .db / .sqlite / .sqlite3 — parsed as SQLite
      • .txt / .csv — scanned as text
    Skips the actual .py source and binary files.
    """
    found = set()
    if not bot_dir or not os.path.isdir(bot_dir):
        return found
    SKIP_EXTS = {".py", ".js", ".enc", ".key", ".png", ".jpg",
                 ".jpeg", ".gif", ".mp4", ".mp3", ".zip", ".tar", ".gz"}
    try:
        for fname in os.listdir(bot_dir):
            fpath = os.path.join(bot_dir, fname)
            if not os.path.isfile(fpath):
                continue
            ext = os.path.splitext(fname)[1].lower()
            if ext in SKIP_EXTS:
                continue
            size = os.path.getsize(fpath)
            if size == 0 or size > 20_000_000:   # skip empty or >20 MB
                continue
            if ext == ".json":
                found.update(_scrape_ids_from_json_file(fpath))
            elif ext in (".db", ".sqlite", ".sqlite3"):
                found.update(_scrape_ids_from_sqlite(fpath))
            elif ext in (".txt", ".csv"):
                found.update(_scrape_ids_from_txt(fpath))
            else:
                # Unknown extension — try text scan
                found.update(_scrape_ids_from_txt(fpath))
    except Exception:
        pass
    return found


async def cb_adm_auto_fetch(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """
    Auto-fetch ALL users from every hosted bot and register them.

    Per-bot sources (all combined):
      1. Bot's data folder  — JSON dbs, SQLite dbs, txt/csv files
      2. Bot's log file     — every user ID ever logged
      3. getUpdates (x2)    — Telegram's buffered pending updates (works when bot is stopped)
      4. hosted_bot_users   — already-stored IDs in the DB table

    Then for each unique ID found: ensure_user() is called to register them
    in the hosting bot's user database.
    """
    q = update.callback_query
    await q.answer("🔄 Fetching users from all hosted bots…")

    pm = await q.edit_message_text(
        "🔄 <b>Auto Fetching Users…</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        "<b>Scanning bot data files, logs, and Telegram updates…</b>",
        parse_mode=ParseMode.HTML,
    )

    bots_checked   = 0
    total_new      = 0
    all_found_ids: set = set()
    errors         = 0

    for bid, b in all_bots().items():
        tok = get_decrypted_bot_token(b) or extract_bot_token(b.get("file_path", ""))
        bots_checked += 1
        bot_ids: set = set()

        try:
            _af_uid_s = str(b.get("user_id", "unknown"))
            bot_dir = os.path.join(BOT_DATA_DIR, _af_uid_s, bid)
            bot_ids.update(_collect_ids_from_bot_folder(bot_dir))
        except Exception:
            errors += 1

        try:
            bot_ids.update(_scrape_ids_from_log(_log_path(bid)))
        except Exception:
            pass

        if tok:
            try:
                res = _tg_get(tok, "getUpdates", {"limit": 100})
                if res.get("ok"):
                    for upd in res.get("result", []):
                        for src in ("message", "callback_query", "edited_message",
                                    "channel_post", "inline_query"):
                            obj = upd.get(src)
                            if obj:
                                u = obj.get("from") or obj.get("message", {}).get("from")
                                if u and u.get("id") and _is_valid_uid(int(u["id"])):
                                    bot_ids.add(int(u["id"]))
                                break
            except Exception:
                pass
            try:
                res2 = _tg_get(tok, "getUpdates", {"limit": 100, "offset": -100})
                if res2.get("ok"):
                    for upd in res2.get("result", []):
                        for src in ("message", "callback_query", "edited_message", "channel_post"):
                            obj = upd.get(src)
                            if obj:
                                u = obj.get("from") or obj.get("message", {}).get("from")
                                if u and u.get("id") and _is_valid_uid(int(u["id"])):
                                    bot_ids.add(int(u["id"]))
                                break
            except Exception:
                pass

        if tok:
            try:
                bot_ids.update(hosted_bot_users_list(tok))
            except Exception:
                pass

        if not bot_ids:
            continue

        if tok:
            try:
                before = len(hosted_bot_users_list(tok))
                add_hosted_bot_users_bulk(tok, list(bot_ids))
                after  = len(hosted_bot_users_list(tok))
                total_new += max(0, after - before)
            except Exception:
                errors += 1

        all_found_ids.update(bot_ids)

        for uid_fetched in bot_ids:
            try:
                if not get_user(uid_fetched):
                    fetched_name  = ""
                    fetched_uname = ""
                    try:
                        chat = await ctx.bot.get_chat(uid_fetched)
                        fetched_name  = getattr(chat, "first_name", "") or ""
                        fetched_uname = getattr(chat, "username",   "") or ""
                    except Exception:
                        pass
                    ensure_user(uid_fetched, fetched_uname, fetched_name)
            except Exception:
                pass

    total_found = len(all_found_ids)
    id_preview  = ""
    if all_found_ids:
        sample   = sorted(all_found_ids)[:20]
        id_lines = "\n".join(f"  • <code>{uid}</code>" for uid in sample)
        more     = f"\n  <b>…and {total_found - 20} more</b>" if total_found > 20 else ""
        id_preview = f"\n\n<b>📋 Registered IDs (sample):</b>\n{id_lines}{more}"

    result_text = (
        f"✅ <b>Auto Fetch Complete!</b>\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"🤖 <b>Bots Scanned:</b>     <b>{bots_checked}</b>\n"
        f"👥 <b>Total IDs Found:</b>  <b>{total_found}</b>\n"
        f"🆕 <b>Newly Registered:</b> <b>{total_new}</b>\n"
        + (f"⚠️ <b>Errors:</b>          <b>{errors}</b>\n" if errors else "")
        + id_preview
        + f"\n\n<b>All fetched users are now registered in the hosting bot.</b>"
    )
    await pm.edit_text(
        result_text,
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
        parse_mode=ParseMode.HTML,
    )


async def _notify_owner_pending(update, ctx, uid: int, bid: str, fp: str, fname: str, bot_username: str = ""):
    tg_user    = update.effective_user
    first_name = h(tg_user.first_name or "")
    username   = f"@{h(tg_user.username)}" if tg_user.username else "<b>no username</b>"
    username_line = f"\n🤖 <b>Bot Username:</b> @{h(bot_username)}" if bot_username else ""
    b_rec = get_bot(bid)
    proj = b_rec.get("project_name","").strip() if b_rec else ""
    project_line = f"\n📁 <b>Project:</b> <code>{h(proj)}</code>" if proj else ""
    send_fp = get_sendable_file_path({"file_path": fp}) or fp
    _tmp_created = (send_fp != fp and os.path.exists(send_fp))
    try:
        with open(send_fp,"rb") as f:
            await ctx.bot.send_document(
                chat_id=OWNER_ID,
                document=f,
                filename=fname,
                caption=(
                    f"📥 <b>New Bot — Approval Required</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"👤 <b>Name:</b>  {first_name}\n"
                    f"🔖 <b>Username:</b> {username}\n"
                    f"🆔 <b>User ID:</b> <code>{uid}</code>\n"
                    f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"📄 <b>File:</b>  <code>{h(fname)}</code>\n"
                    f"🔑 <b>Bot ID:</b> <code>{bid}</code>"
                    f"{project_line}"
                    f"{username_line}\n\n"
                    f"<b>Review the file, then approve or reject.</b>"
                ),
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("✅ Approve", callback_data=f"adm_approve_{uid}_{bid}", style="success"),
                     InlineKeyboardButton("❌ Reject",  callback_data=f"adm_reject_{uid}_{bid}", style="danger")],
                ]),
                parse_mode=ParseMode.HTML,
            )
    except Exception as e:
        log.warning("Could not forward file to owner: %s", e)
    finally:
        if _tmp_created and os.path.exists(send_fp):
            try:
                os.remove(send_fp)
            except Exception:
                pass

async def _notify_owner_upload_viewonly(ctx, uid: int, bid: str, fp: str, fname: str, tg_user, label: str = "📤 <b>New Upload</b>"):
    username   = f"@{h(tg_user.username)}" if tg_user.username else "<b>no username</b>"
    first_name = h(tg_user.first_name or "N/A")
    u = get_user(uid)
    plan_key  = u.get("plan", "free") if u else "free"
    plan_info = PLANS.get(plan_key, PLANS["free"])
    plan_line = f"{plan_info['emoji']} <b>{plan_info['name']}</b>"
    caption = (
        f"{label}\n"
        f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
        f"📄 <b>File</b>   ·  <code>{h(fname)}</code>\n"
        f"👤 <b>User</b>   ·  {first_name}  ({username})\n"
        f"🆔 <b>ID</b>     ·  <code>{uid}</code>  |  {plan_line}"
    )
    kb = InlineKeyboardMarkup([[InlineKeyboardButton("📂 View Files", callback_data=f"adm_ufiles_{uid}", style="primary")]])
    send_fp = get_sendable_file_path({"file_path": fp}) or fp
    _tmp_created = (send_fp != fp and os.path.exists(send_fp))
    try:
        with open(send_fp, "rb") as f:
            await ctx.bot.send_document(
                chat_id=OWNER_ID,
                document=f,
                filename=fname,
                caption=caption,
                reply_markup=kb,
                parse_mode=ParseMode.HTML,
            )
    except Exception as e:
        log.warning("Could not notify owner of plan upload: %s", e)
        try:
            await ctx.bot.send_message(chat_id=OWNER_ID, text=caption, reply_markup=kb, parse_mode=ParseMode.HTML)
        except Exception:
            pass
    finally:
        if _tmp_created and os.path.exists(send_fp):
            try:
                os.remove(send_fp)
            except Exception:
                pass

#  UNIVERSAL MESSAGE HANDLER

async def on_message(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    uid = update.effective_user.id

    if uid != OWNER_ID and is_rate_limited(uid):
        try:
            await update.message.reply_text(
                "⚠️ <b>Slow down!</b> You're sending too fast. Please wait a moment.",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
        return

    if is_banned(uid):
        await update.message.reply_text("<b>🚫 You're Banned</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>You no longer have access to this bot.</b>", parse_mode=ParseMode.HTML)
        return

    # Admin states are allowed through so admin panel keeps working.
    # Regular users in a non-admin state must pass force join.
    state = get_st(ctx)
    _is_admin_state = (uid == OWNER_ID and state and state.startswith("adm_"))
    if not _is_admin_state and uid != OWNER_ID:
        fj_ok = await check_force_join(update, ctx)
        if not fj_ok:
            return

    text      = (update.message.text or "").strip()
    doc       = update.message.document
    photo     = update.message.photo
    sticker   = update.message.sticker
    animation = update.message.animation

    if state == "adm_find_user_id" and uid == OWNER_ID:
        if not text or not text.strip().lstrip("-").isdigit():
            await update.message.reply_text(
                "❌ <b>Please send a valid numeric User ID.</b>",
                parse_mode=ParseMode.HTML,
            )
            return
        lookup_uid = int(text.strip())
        clr_st(ctx)
        u = get_user(lookup_uid)
        if not u:
            # Try to fetch from Telegram even if not registered
            fetched_name = ""
            fetched_uname = ""
            try:
                chat = await ctx.bot.get_chat(lookup_uid)
                fetched_name  = getattr(chat, "first_name", "") or ""
                fetched_uname = getattr(chat, "username",   "") or ""
            except Exception:
                pass
            if fetched_name or fetched_uname:
                tag = f"@{fetched_uname}" if fetched_uname else fetched_name
                await update.message.reply_text(
                    f"❌ <b>User <code>{lookup_uid}</code> not registered</b> in this bot.\n\n"
                    f"📛 <b>Telegram name:</b> {h(tag)}\n\n"
                    f"<b>They have never used this bot.</b>",
                    reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
                    parse_mode=ParseMode.HTML,
                )
            else:
                await update.message.reply_text(
                    f"❌ <b>User <code>{lookup_uid}</code> not found.</b>\n\n"
                    f"<b>Not registered and not reachable on Telegram.</b>",
                    reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
                    parse_mode=ParseMode.HTML,
                )
            return
        uid_s  = str(lookup_uid)
        banned = is_banned(lookup_uid)
        p = u.get("plan","free")
        if p not in PLANS:
            p = "free"
        pl = PLANS[p]
        override = u.get("approval_override")
        approval_status = "Enabled (override)" if override is True else ("Disabled (override)" if override is False else "Default")
        ram_lim_str = "Unlimited ♾️" if pl.get("ram_mb", 0) == UNLIMITED_SENTINEL else f"{pl.get('ram_mb', 0)} MB"
        text_out = (
            f"🔍 <b>User Profile</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"👤 <b>Name:</b>     {h(user_display(uid_s, u))}\n"
            f"🆔 <b>ID:</b>       <code>{uid_s}</code>\n"
            f"👤 <b>Username:</b> @{h(u.get('username') or 'N/A')}\n"
            f"{pl['emoji']} <b>Plan:</b>     <b>{pl['name']}</b>\n"
            f"📅 <b>Expiry:</b>   {fmt_expiry(u.get('expiry'))}\n"
            f"📁 <b>Files:</b>    <b>{len(u.get('bots',[]))}</b>\n"
            f"🧠 <b>RAM Limit:</b> <b>{ram_lim_str}</b>\n"
            f"🛡 <b>Approval:</b> <b>{approval_status}</b>\n"
            f"🚫 <b>Banned:</b>   {'<b>Yes</b>' if banned else 'No'}"
        )
        ban_btn = (
            InlineKeyboardButton("✅ Unban", callback_data=f"adm_unban_id_{uid_s}", style="success")
            if banned else
            InlineKeyboardButton("🚫 Ban",   callback_data=f"adm_ban_id_{uid_s}", style="danger")
        )
        await update.message.reply_text(
            text_out,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📂 View Files", callback_data=f"adm_ufiles_{uid_s}", style="primary"),
                 InlineKeyboardButton("🎁 Give Sub",   callback_data=f"adm_givesub_{uid_s}", style="success")],
                [InlineKeyboardButton("✅ Enable Approval",  callback_data=f"adm_set_approval_{uid_s}_on", style="success"),
                 InlineKeyboardButton("❌ Disable Approval", callback_data=f"adm_set_approval_{uid_s}_off", style="primary")],
                [ban_btn],
                [InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")],
            ]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_reject_reason" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ <b>Send a text reason, or tap Skip Reason.</b>", parse_mode=ParseMode.HTML)
            return
        uid_s = ctx.user_data.get("reject_uid")
        bid   = ctx.user_data.get("reject_bid")
        prompt_msg_id = ctx.user_data.get("reject_msg_id")
        prompt_chat_id = ctx.user_data.get("reject_chat_id")
        clr_st(ctx)
        if not uid_s or not bid:
            await update.message.reply_text("❌ <b>Reject session expired.</b>", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]), parse_mode=ParseMode.HTML)
            return
        result_text = await finalize_admin_rejection(ctx, str(uid_s), str(bid), text)
        # Delete the "Send the reason…" prompt message so it doesn't linger
        # unchanged in the chat, then send the final result as a fresh message.
        if prompt_msg_id and prompt_chat_id:
            try:
                await ctx.bot.delete_message(chat_id=prompt_chat_id, message_id=prompt_msg_id)
            except Exception:
                pass
        await update.message.reply_text(result_text, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]), parse_mode=ParseMode.HTML)
        return

    if state == "adm_pay_deny_reason" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ Send a denial reason.", parse_mode=ParseMode.HTML)
            return
        deny_uid_s = ctx.user_data.get("deny_uid","")
        clr_st(ctx)
        del_payment_pending(int(deny_uid_s))
        try:
            await ctx.bot.send_message(
                chat_id=int(deny_uid_s),
                text=(
                    f"❌ <b>Payment Denied</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"📝 <b>Reason:</b> <b>{h(text)}</b>\n\n"
                    f"<b>Contact @{DEVELOPER_USERNAME} for support.</b>"
                ),
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
        await update.message.reply_text(
            f"❌ <b>Payment Denied</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"👤 <b>User ID:</b> <code>{deny_uid_s}</code>\n"
            f"📝 <b>Reason:</b> {h(text)}\n\n"
            f"<b>User notified.</b>",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Payments", callback_data="adm_payments", style="primary")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "redeem":
        if not text:
            await update.message.reply_text("❌ <b>Send a text code.</b>", parse_mode=ParseMode.HTML)
            return
        ok, msg = use_code(text, uid)
        clr_st(ctx)
        await update.message.reply_text(msg, reply_markup=kb_main(), parse_mode=ParseMode.HTML)
        return

    if state == "pip_install":
        if not text:
            await update.message.reply_text("❌ <b>Send package name(s).</b>", parse_mode=ParseMode.HTML)
            return
        pip_text = text.strip()
        # Strip common pip command prefixes users might paste
        for _pfx in ("pip3 install", "pip install", "pip3", "pip"):
            if pip_text.lower().startswith(_pfx.lower()):
                pip_text = pip_text[len(_pfx):].strip()
                break
        # Reject -r requirements.txt syntax (unsupported in this interface)
        if re.search(r"(?:^|\s)-r\s", pip_text):
            await update.message.reply_text(
                "❌ <b>-r requirements.txt is not supported here.</b>\n"
                "Please send package names directly, e.g.:\n"
                "<code>pyrogram tgcrypto aiohttp</code>",
                parse_mode=ParseMode.HTML,
            )
            return
        # Strip flags users might accidentally include
        pip_text = re.sub(r"(?:^|\s)--(?:upgrade|user|quiet|force-reinstall)\b|(?:^|\s)-[Uq]\b", " ", pip_text).strip()
        try:
            packages = shlex.split(pip_text)
        except ValueError as e:
            await update.message.reply_text(f"❌ Invalid input: <code>{h(e)}</code>", parse_mode=ParseMode.HTML)
            return
        if not packages:
            await update.message.reply_text("❌ <b>Send package name(s).</b>", parse_mode=ParseMode.HTML)
            return
        bad = [p for p in packages if not re.match(r"^[A-Za-z0-9_.\-\[\]=<>~,!]+$", p)]
        if bad:
            await update.message.reply_text(f"❌ Invalid package name: <code>{h(bad[0])}</code>", parse_mode=ParseMode.HTML)
            return
        pm = await update.message.reply_text(f"📦 <b>Installing: <code>{h(', '.join(packages))}</code>…</b>", parse_mode=ParseMode.HTML)
        pip_error_button = InlineKeyboardMarkup([
            [InlineKeyboardButton("📄 See Error", callback_data="pip_error", style="primary")],
            [InlineKeyboardButton("🔙 Back", callback_data="pip_management", style="primary"),
             InlineKeyboardButton("🏠 Home", callback_data="home", style="primary")],
        ])
        try:
            pip_ok, pip_msg = ensure_pip_available()
            if not pip_ok:
                clr_st(ctx)
                PIP_ERRORS[uid] = {"type":"pip_not_exist","error":pip_msg}
                await pm.edit_text("❌ <b>pip not found.</b> Tap See Error for details.", reply_markup=pip_error_button, parse_mode=ParseMode.HTML)
                return
            rc, out = _pip_install_pkg(packages)
            clr_st(ctx)
            if len(out) > 2500:
                out = "…(truncated)\n" + out[-2500:]
            if rc == 0:
                PIP_ERRORS.pop(uid, None)
                await pm.edit_text(
                      f"✅ <b>Successfully installed:</b> <code>{h(', '.join(packages))}</code>",
                      reply_markup=InlineKeyboardMarkup([
                          [InlineKeyboardButton("🔙 Back", callback_data="pip_management", style="primary"),
                           InlineKeyboardButton("🏠 Home", callback_data="home", style="primary")],
                      ]),
                      parse_mode=ParseMode.HTML,
                )
            else:
                PIP_ERRORS[uid] = {"type": "pip_install_failed", "error": out}
                await pm.edit_text("❌ <b>Installation failed.</b> Tap See Error for details.", reply_markup=pip_error_button, parse_mode=ParseMode.HTML)
        except subprocess.TimeoutExpired:
            clr_st(ctx)
            PIP_ERRORS[uid] = {"type":"pip_timeout","error":"Installation timed out."}
            await pm.edit_text("❌ <b>Installation timed out.</b>", reply_markup=pip_error_button, parse_mode=ParseMode.HTML)
        except Exception as e:
            clr_st(ctx)
            PIP_ERRORS[uid] = {"type":type(e).__name__,"error":str(e)}
            await pm.edit_text("❌ <b>Installation error.</b> Tap See Error for details.", reply_markup=pip_error_button, parse_mode=ParseMode.HTML)
        return

    if state == "pip_uninstall":
        if not text:
            await update.message.reply_text("❌ <b>Send package name(s) to uninstall.</b>", parse_mode=ParseMode.HTML)
            return
        pip_text = text.strip()
        try:
            packages = shlex.split(pip_text)
        except ValueError as e:
            await update.message.reply_text(f"❌ Invalid input: <code>{h(e)}</code>", parse_mode=ParseMode.HTML)
            return
        if not packages:
            await update.message.reply_text("❌ <b>Send package name(s) to uninstall.</b>", parse_mode=ParseMode.HTML)
            return
        bad = [p for p in packages if not re.match(r"^[A-Za-z0-9_.\-\[\]=<>~,!]+$", p)]
        if bad:
            await update.message.reply_text(f"❌ Invalid package name: <code>{h(bad[0])}</code>", parse_mode=ParseMode.HTML)
            return
        pm = await update.message.reply_text(f"🗑️ <b>Uninstalling: <code>{h(', '.join(packages))}</code>…</b>", parse_mode=ParseMode.HTML)
        pip_error_button = InlineKeyboardMarkup([
            [InlineKeyboardButton("📄 See Error", callback_data="pip_error", style="primary")],
            [InlineKeyboardButton("🔙 Back", callback_data="pip_management", style="primary"),
             InlineKeyboardButton("🏠 Home", callback_data="home", style="primary")],
        ])
        try:
            pip_ok, pip_msg = ensure_pip_available()
            if not pip_ok:
                clr_st(ctx)
                PIP_ERRORS[uid] = {"type": "pip_not_exist", "error": pip_msg}
                await pm.edit_text("❌ <b>pip not found.</b> Tap See Error for details.", reply_markup=pip_error_button, parse_mode=ParseMode.HTML)
                return
            result = subprocess.run(
                [sys.executable, "-m", "pip", "uninstall", "-y", *packages],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=PIP_INSTALL_TIMEOUT,
            )
            clr_st(ctx)
            out = (result.stdout or "").strip()
            if len(out) > 2500:
                out = "…(truncated)\n" + out[-2500:]
            if result.returncode == 0:
                PIP_ERRORS.pop(uid, None)
                # A package just disappeared from the shared environment —
                # any bot previously marked "verified" might depend on it,
                # so force every bot to re-scan its imports on next start.
                invalidate_import_verification()
                await pm.edit_text(
                    f"✅ <b>Successfully uninstalled:</b> <code>{h(', '.join(packages))}</code>",
                    reply_markup=InlineKeyboardMarkup([
                        [InlineKeyboardButton("🔙 Back", callback_data="pip_management", style="primary"),
                         InlineKeyboardButton("🏠 Home", callback_data="home", style="primary")],
                    ]),
                    parse_mode=ParseMode.HTML,
                )
            else:
                PIP_ERRORS[uid] = {"type": "pip_uninstall_failed", "error": out}
                await pm.edit_text("❌ <b>Uninstall failed.</b> Tap See Error for details.", reply_markup=pip_error_button, parse_mode=ParseMode.HTML)
        except subprocess.TimeoutExpired:
            clr_st(ctx)
            PIP_ERRORS[uid] = {"type": "pip_timeout", "error": "Uninstall timed out."}
            await pm.edit_text("❌ <b>Uninstall timed out.</b>", reply_markup=pip_error_button, parse_mode=ParseMode.HTML)
        except Exception as e:
            clr_st(ctx)
            PIP_ERRORS[uid] = {"type": type(e).__name__, "error": str(e)}
            await pm.edit_text("❌ <b>Uninstall error.</b> Tap See Error for details.", reply_markup=pip_error_button, parse_mode=ParseMode.HTML)
        return

    if state == "upload":
        if not doc:
            await update.message.reply_text("❌ Send a file: <code>.py</code>", parse_mode=ParseMode.HTML)
            return
        if not doc.file_name or not is_allowed_file(doc.file_name):
            await update.message.reply_text("❌ <b>Only .py files are accepted.</b>", parse_mode=ParseMode.HTML)
            return
        if doc.file_size > MAX_BYTES:
            await update.message.reply_text(
                (
                    "❌ <b>File Too Large</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"📦 <b>Your File:</b> <code>{doc.file_size/1024/1024:.2f} MB</code>\n"
                    f"📏 <b>Max Allowed:</b> <code>25 MB</code>"
                ),
                parse_mode=ParseMode.HTML,
            )
            return
        check_expiry(uid)
        if not is_unlimited(uid) and bot_count(uid) >= get_file_limit(uid):
            clr_st(ctx)
            await update.message.reply_text(
                (
                    "❌ <b>File Limit Reached</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"📂 <b>Bots Hosted:</b> <code>{bot_count(uid)} / {get_file_limit(uid)}</code>\n\n"
                    "🚀 <b>Upgrade your plan to host more bots!</b>"
                ),
                reply_markup=kb_main(), parse_mode=ParseMode.HTML,
            )
            return
        pm = await update.message.reply_text("⏳ <b>Uploading…</b>", parse_mode=ParseMode.HTML)
        tg_file  = await ctx.bot.get_file(doc.file_id)
        user_dir = os.path.join(HOSTED_FILES_DIR, str(uid))
        bid = str(uuid.uuid4())[:8]
        bot_dir = os.path.join(user_dir, bid)
        os.makedirs(bot_dir, exist_ok=True)
        saved_name = safe_filename(doc.file_name)
        fp  = os.path.join(bot_dir, saved_name)
        await tg_file.download_to_drive(fp)

        # Bot-token detection — every hosted file must be a working Telegram
        # bot, so reject up front (before it ever becomes a hosted bot
        # entry) if no token is present anywhere in the file.
        bot_tok = extract_bot_token(fp) or ""
        if not bot_tok:
            try:
                shutil.rmtree(bot_dir, ignore_errors=True)
            except Exception:
                pass
            clr_st(ctx)
            await pm.edit_text(
                "❌ <b>Bot Token Not Found</b>\n"
                "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                "🚫 <b>Bot Token Not Found In File.</b>\n"
                "📌 <b>Please Add Your Bot Token In The File First.</b>\n"
                "🔁 <b>Then Upload The File Again.</b>",
                reply_markup=kb_main(),
                parse_mode=ParseMode.HTML,
            )
            return

        usr  = get_user(uid)
        plan = usr.get("plan","free") if usr else "free"
        if plan not in PLANS:
            plan = "free"
        is_pending = needs_approval(uid)
        project_name = ctx.user_data.get("project_name", "")
        add_bot(uid, bid, doc.file_name, fp, pending=is_pending, bot_token=bot_tok, project_name=project_name)
        if bot_tok:
            add_hosted_bot_users_bulk(bot_tok,[])

        enc_fp = encrypt_bot_file(fp)
        if enc_fp:
            upd_bot(bid, {"file_path": enc_fp})
            fp = enc_fp

        project_line = f"📁 <b>Project:</b> <code>{h(project_name)}</code>\n" if project_name else ""
        clr_st(ctx)
        if is_pending:
            auto_username = await auto_fetch_bot_username(bot_tok)
            try:
                await _notify_owner_pending(update, ctx, uid, bid, fp, doc.file_name, auto_username)
            except Exception:
                pass
            await pm.edit_text(
                f"📤 <b>Upload Sent for Approval!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"{project_line}"
                f"📄 <b>File:</b>  <code>{h(doc.file_name)}</code>\n"
                f"🆔 <b>ID:</b>    <code>{bid}</code>\n\n"
                f"⏳ <b>Pending owner approval.</b>\n"
                f"<b>You will be notified once it's approved or rejected.</b>",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🤖 My Bots", callback_data="mybots", style="primary")],
                    [InlineKeyboardButton("🏠 Home",     callback_data="home", style="primary")],
                ]), parse_mode=ParseMode.HTML,
            )
        else:
            try:
                await _notify_owner_upload_viewonly(ctx, uid, bid, fp, doc.file_name, update.effective_user)
            except Exception:
                pass
            await pm.edit_text(
                f"✅ <b>Upload Successful!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"{project_line}"
                f"📄 <b>File:</b>  <code>{h(doc.file_name)}</code>\n"
                f"🆔 <b>ID:</b>    <code>{bid}</code>\n\n"
                f"<b>Tap Start Now to run your bot.</b>",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("▶️ Start Now", callback_data=f"bact_start_{bid}", style="success"),
                     InlineKeyboardButton("🤖 My Bots",   callback_data="mybots", style="primary")],
                    [InlineKeyboardButton("🏠 Home", callback_data="home", style="primary")],
                ]), parse_mode=ParseMode.HTML,
            )
        return

    if state == "awaiting_payment_ss":
        plan_key = ctx.user_data.get("payment_plan","baby")
        clr_st(ctx)
        if not photo and not doc:
            await update.message.reply_text("❌ <b>Send a screenshot (photo) of your payment.</b>", parse_mode=ParseMode.HTML)
            return
        pl = PLANS.get(plan_key, PLANS["baby"])
        fwd_msg_id = update.message.message_id
        add_payment_pending(uid, plan_key, fwd_msg_id, update.message.chat_id)
        try:
            u = get_user(uid)
            uname = f"@{u.get('username')}" if u and u.get("username") else f"id:{uid}"
            await update.message.forward(chat_id=OWNER_ID)
            await ctx.bot.send_message(
                chat_id=OWNER_ID,
                text=(
                    f"💳 <b>New Payment Screenshot</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"👤 <b>User:</b> {h(uname)} (<code>{uid}</code>)\n"
                    f"{pl['emoji']} <b>Plan:</b> <b>{pl['name']}</b> — {pl['price']}\n\n"
                    f"<b>Verify or deny above.</b>"
                ),
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("✅ Verify",  callback_data=f"adm_pay_verify_{uid}", style="success"),
                     InlineKeyboardButton("❌ Deny",    callback_data=f"adm_pay_deny_{uid}", style="danger")],
                ]),
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
        await update.message.reply_text(
            f"✅ <b>Payment Screenshot Received!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"{pl['emoji']} <b>Plan:</b> <b>{pl['name']}</b>\n\n"
            f"<b>Your payment has been forwarded to the owner for verification.\n"
            f"You will be notified once verified.</b>",
            reply_markup=kb_main(),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_set_qr_img" and uid == OWNER_ID:
        if not photo:
            await update.message.reply_text("❌ <b>Send a photo of the QR code.</b>", parse_mode=ParseMode.HTML)
            return
        best = max(photo, key=lambda p: p.file_size)
        tg_file = await ctx.bot.get_file(best.file_id)
        qr_path = os.path.join(BASE_DIR, "payment_qr.jpg")
        await tg_file.download_to_drive(qr_path)
        upd_settings({"payment_qr": qr_path})
        backup_status = ""
        try:
            old_backup_id = get_setting("qr_backup_msg_id", "")
            if old_backup_id:
                try:
                    await ctx.bot.delete_message(chat_id=CLOUD_STORAGE_CHAT_ID, message_id=int(old_backup_id))
                except Exception:
                    pass
            with open(qr_path, "rb") as qr_f:
                backup_msg = await ctx.bot.send_photo(
                    chat_id=CLOUD_STORAGE_CHAT_ID,
                    photo=qr_f,
                    caption=f"#QR_BACKUP\nPayment QR Code\nUpdated: {_now_ist():%Y-%m-%d %H:%M IST}",
                )
            upd_settings({"qr_backup_msg_id": str(backup_msg.message_id)})
            backup_status = "\n☁️ <b>QR backed up to cloud channel.</b>"
        except Exception as _qr_bk_err:
            backup_status = f"\n⚠️ <b>Cloud backup failed: {h(str(_qr_bk_err))}</b>"
        clr_st(ctx)
        await update.message.reply_text(
            f"✅ <b>Payment QR Code Updated!</b>{backup_status}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_set_upi" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ <b>Send your UPI ID as text.</b>", parse_mode=ParseMode.HTML)
            return
        upi = text.strip()
        upd_settings({"payment_upi": upi})
        clr_st(ctx)
        await update.message.reply_text(
            f"✅ <b>UPI ID Saved!</b>\n\n📲 <b>UPI:</b> <code>{h(upi)}</code>",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_new_plan_name" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ <b>Please send the plan name as text.</b>", parse_mode=ParseMode.HTML)
            return
        name = sanitize_input(text, max_len=40)
        set_st(ctx, "adm_new_plan_file_limit", np_name=name)
        await update.message.reply_text(
            f"➕ <b>New Plan — Step 2/4</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📝 <b>Plan Name:</b> <code>{h(name)}</code>\n\n"
            f"📁 <b>How many files can users host?</b>\n"
            f"Send a number (e.g. <code>30</code>) or <code>0</code> for unlimited:",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_new_plan_file_limit" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ <b>Send a number for the file limit.</b>", parse_mode=ParseMode.HTML)
            return
        try:
            lim = int(text.strip())
        except ValueError:
            await update.message.reply_text("❌ <b>Invalid number. Send a whole number.</b>", parse_mode=ParseMode.HTML)
            return
        file_limit = UNLIMITED_SENTINEL if lim == 0 else lim
        set_st(ctx, "adm_new_plan_approval",
               np_name=ctx.user_data.get("np_name",""),
               np_file_limit=file_limit)
        await update.message.reply_text(
            f"➕ <b>New Plan — Step 3/4</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📁 <b>File Limit:</b> {'Unlimited' if lim == 0 else lim}\n\n"
            f"⏳ <b>Does this plan require admin approval before bots run?</b>\n"
            f"Send <code>yes</code> or <code>no</code>:",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_new_plan_approval" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ <b>Send yes or no.</b>", parse_mode=ParseMode.HTML)
            return
        val = text.strip().lower()
        if val not in ("yes","no","y","n"):
            await update.message.reply_text("❌ <b>Send yes or no.</b>", parse_mode=ParseMode.HTML)
            return
        approval = (val in ("yes","y"))
        set_st(ctx, "adm_new_plan_price",
               np_name=ctx.user_data.get("np_name",""),
               np_file_limit=ctx.user_data.get("np_file_limit", 5),
               np_approval=approval)
        await update.message.reply_text(
            f"➕ <b>New Plan — Step 4/4</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"⏳ <b>Approval Required:</b> {'Yes' if approval else 'No'}\n\n"
            f"💰 <b>What is the price?</b>\n"
            f"Send as text (e.g. <code>₹149 / Month</code> or <code>Free</code>):",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_new_plan_price" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ <b>Send the price as text.</b>", parse_mode=ParseMode.HTML)
            return
        price = sanitize_input(text.strip(), max_len=60)
        np_name     = ctx.user_data.get("np_name", "Custom")
        np_lim      = ctx.user_data.get("np_file_limit", 5)
        np_approval = ctx.user_data.get("np_approval", True)
        plan_key    = re.sub(r"[^a-z0-9_]", "", np_name.lower().replace(" ","_"))[:20] or "custom"
        custom_plans = get_custom_plans()
        if plan_key in PLANS:
            plan_key = plan_key + "_custom"
        custom_plans[plan_key] = {
            "name":       np_name,
            "emoji":      "🌟",
            "file_limit": np_lim,
            "price":      price,
            "duration_days": 30,
            "approval":   np_approval,
        }
        save_custom_plans(custom_plans)
        clr_st(ctx)
        await update.message.reply_text(
            f"✅ <b>New Plan Created!</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"🌟 <b>Name:</b>       <code>{h(np_name)}</code>\n"
            f"📁 <b>File Limit:</b> {'Unlimited' if np_lim == UNLIMITED_SENTINEL else np_lim}\n"
            f"⏳ <b>Approval:</b>   {'Required' if np_approval else 'Not Required'}\n"
            f"💰 <b>Price:</b>      {h(price)}\n"
            f"🔑 <b>Key:</b>        <code>{plan_key}</code>\n\n"
            f"<b>Use Create Code to issue codes for this plan.</b>",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_edit_plan_price" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ <b>Send the new price as text.</b>", parse_mode=ParseMode.HTML)
            return
        plan_key = ctx.user_data.get("edit_plan_key", "")
        all_pl   = get_all_plans()
        if plan_key not in all_pl:
            clr_st(ctx)
            await update.message.reply_text("❌ <b>Plan not found.</b>", parse_mode=ParseMode.HTML)
            return
        raw = text.strip()
        new_price = None if raw == "-" else sanitize_input(raw, max_len=60)
        set_st(ctx, "adm_edit_plan_duration", edit_plan_key=plan_key, edit_plan_price=new_price)
        await update.message.reply_text(
            f"🔧 <b>Edit Plan — Step 2/4: Duration</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"💰 <b>Price:</b> {h(new_price) if new_price else '(unchanged)'}\n\n"
            f"📅 <b>Send the new duration in days</b>\n"
            f"(e.g. <code>30</code> monthly, <code>365</code> yearly, <code>0</code> to keep current):",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_manage_plans", style="danger")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_edit_plan_duration" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ <b>Send the number of days.</b>", parse_mode=ParseMode.HTML)
            return
        try:
            new_days = int(text.strip())
        except ValueError:
            await update.message.reply_text("❌ <b>Invalid number. Send a whole number of days.</b>", parse_mode=ParseMode.HTML)
            return
        plan_key  = ctx.user_data.get("edit_plan_key", "")
        new_price = ctx.user_data.get("edit_plan_price", None)
        all_pl    = get_all_plans()
        if plan_key not in all_pl:
            clr_st(ctx)
            await update.message.reply_text("❌ <b>Plan not found.</b>", parse_mode=ParseMode.HTML)
            return
        set_st(ctx, "adm_edit_plan_file_limit",
               edit_plan_key=plan_key, edit_plan_price=new_price, edit_plan_days=new_days)
        cur_lim = all_pl[plan_key].get("file_limit", 0)
        cur_lim_str = "Unlimited" if cur_lim == UNLIMITED_SENTINEL else str(cur_lim)
        await update.message.reply_text(
            f"🔧 <b>Edit Plan — Step 3/4: File Limit</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📅 <b>Duration:</b> {new_days if new_days > 0 else 'unchanged'} day(s)\n"
            f"📁 <b>Current File Limit:</b> {cur_lim_str}\n\n"
            f"📁 <b>Send the new file limit</b>\n"
            f"(number, e.g. <code>30</code>; <code>0</code> for unlimited; <code>-</code> to keep current):",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_manage_plans", style="danger")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_edit_plan_file_limit" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ <b>Send a number or <code>-</code> to skip.</b>", parse_mode=ParseMode.HTML)
            return
        plan_key  = ctx.user_data.get("edit_plan_key", "")
        new_price = ctx.user_data.get("edit_plan_price", None)
        new_days  = ctx.user_data.get("edit_plan_days", 0)
        all_pl    = get_all_plans()
        if plan_key not in all_pl:
            clr_st(ctx)
            await update.message.reply_text("❌ <b>Plan not found.</b>", parse_mode=ParseMode.HTML)
            return
        raw = text.strip()
        new_file_limit = None
        if raw != "-":
            try:
                lim_val = int(raw)
                new_file_limit = UNLIMITED_SENTINEL if lim_val == 0 else lim_val
            except ValueError:
                await update.message.reply_text("❌ <b>Invalid. Send a number or <code>-</code> to skip.</b>", parse_mode=ParseMode.HTML)
                return
        set_st(ctx, "adm_edit_plan_approval_req",
               edit_plan_key=plan_key, edit_plan_price=new_price,
               edit_plan_days=new_days, edit_plan_file_limit=new_file_limit)
        cur_approval = all_pl[plan_key].get("approval", False)
        await update.message.reply_text(
            f"🔧 <b>Edit Plan — Step 4/4: Approval</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📁 <b>File Limit:</b> {'Unlimited' if new_file_limit == UNLIMITED_SENTINEL else (new_file_limit if new_file_limit is not None else 'unchanged')}\n"
            f"✅ <b>Current Approval:</b> {'Yes' if cur_approval else 'No'}\n\n"
            f"⏳ <b>Require admin approval for this plan?</b>\n"
            f"Send <code>yes</code> or <code>no</code> (or <code>-</code> to keep current):",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_manage_plans", style="danger")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_edit_plan_approval_req" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ <b>Send yes, no, or <code>-</code> to skip.</b>", parse_mode=ParseMode.HTML)
            return
        plan_key       = ctx.user_data.get("edit_plan_key", "")
        new_price      = ctx.user_data.get("edit_plan_price", None)
        new_days       = ctx.user_data.get("edit_plan_days", 0)
        new_file_limit = ctx.user_data.get("edit_plan_file_limit", None)
        all_pl         = get_all_plans()
        if plan_key not in all_pl:
            clr_st(ctx)
            await update.message.reply_text("❌ <b>Plan not found.</b>", parse_mode=ParseMode.HTML)
            return
        raw = text.strip().lower()
        new_approval = None
        if raw in ("yes", "y"):
            new_approval = True
        elif raw in ("no", "n"):
            new_approval = False
        elif raw != "-":
            await update.message.reply_text("❌ <b>Send yes, no, or <code>-</code> to skip.</b>", parse_mode=ParseMode.HTML)
            return
        custom_plans = get_custom_plans()
        base = dict(all_pl[plan_key])
        if plan_key in PLANS:
            if plan_key not in custom_plans:
                custom_plans[plan_key] = dict(PLANS[plan_key])
        if plan_key not in custom_plans:
            custom_plans[plan_key] = dict(base)
        if new_price is not None:
            custom_plans[plan_key]["price"] = new_price
            if plan_key in PLANS:
                PLANS[plan_key]["price"] = new_price
        if new_days > 0:
            custom_plans[plan_key]["duration_days"] = new_days
            if plan_key in PLANS:
                PLANS[plan_key]["duration_days"] = new_days
        if new_file_limit is not None:
            custom_plans[plan_key]["file_limit"] = new_file_limit
            if plan_key in PLANS:
                PLANS[plan_key]["file_limit"] = new_file_limit
        if new_approval is not None:
            custom_plans[plan_key]["approval"] = new_approval
            if plan_key in PLANS:
                PLANS[plan_key]["approval"] = new_approval
        save_custom_plans(custom_plans)
        clr_st(ctx)
        updated_pl = get_all_plans().get(plan_key, {})
        lim_final = updated_pl.get("file_limit", 0)
        lim_final_str = "Unlimited" if lim_final == UNLIMITED_SENTINEL else str(lim_final)
        await update.message.reply_text(
            f"✅ <b>Plan Updated!</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"🔑 <b>Plan:</b>      <code>{plan_key}</code>\n"
            f"💰 <b>Price:</b>     {h(updated_pl.get('price','N/A'))}\n"
            f"📅 <b>Duration:</b>  {updated_pl.get('duration_days','N/A')} day(s)\n"
            f"📁 <b>File Limit:</b> {lim_final_str}\n"
            f"✅ <b>Approval:</b>  {'Required' if updated_pl.get('approval', False) else 'Not Required'}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔧 Manage Plans", callback_data="adm_manage_plans", style="primary")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_set_custom_uptime" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ <b>Send your custom uptime message as text.</b>", parse_mode=ParseMode.HTML)
            return
        val = text.strip()
        if val.lower() == "clear":
            upd_settings({"custom_uptime": ""})
            clr_st(ctx)
            await update.message.reply_text(
                "✅ <b>Custom Uptime Cleared.</b>",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
                parse_mode=ParseMode.HTML,
            )
        else:
            upd_settings({"custom_uptime": val})
            clr_st(ctx)
            await update.message.reply_text(
                f"✅ <b>Custom Uptime Saved!</b>\n\n⏱️ <b>Message:</b> <code>{h(val)}</code>\n\n"
                f"<b>Users will see this in their Bot Uptime page.</b>",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
                parse_mode=ParseMode.HTML,
            )
        return

    if state == "adm_fj_add_channel_title" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ <b>Send a button title as text.</b>", parse_mode=ParseMode.HTML)
            return
        title = sanitize_input(text.strip(), max_len=60)
        set_st(ctx, "adm_fj_add_channel_link", fj_title=title)
        await update.message.reply_text(
            f"➕ <b>Add Force Join Channel — Step 2/2</b>\n\n"
            f"<b>Button title:</b> <code>{h(title)}</code>\n\n"
            f"<b>Now send the channel link</b> (public or private invite):\n\n"
            f"<b>Examples:\n"
            f"• <code>https://t.me/MyChannel</code> (public)\n"
            f"• <code>https://t.me/+AbcDefGhiJkl</code> (private invite)\n"
            f"• <code>@MyChannel</code> (username only — link auto-generated)</b>\n\n"
            f"<b>ℹ️ For public channels:</b> Bot verifies join via Telegram API automatically.\n"
            f"<b>ℹ️ For private channels:</b> Add the bot as admin to the channel/group.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_force_join", style="success")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_fj_add_channel_link" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ <b>Send the channel link or @username.</b>", parse_mode=ParseMode.HTML)
            return
        raw = text.strip()
        title = ctx.user_data.get("fj_title", "Channel")
        if raw.startswith("@"):
            username = raw
            link = f"https://t.me/{raw.lstrip('@')}"
        elif raw.startswith("https://t.me/"):
            link = raw
            slug = raw.split("https://t.me/", 1)[1].split("/")[0]
            if slug.startswith("+"):
                username = raw  # use full link as identifier
            else:
                username = f"@{slug}"
        else:
            username = f"@{raw.lstrip('@')}"
            link = f"https://t.me/{raw.lstrip('@')}"
        add_force_join_channel_with_title(username, link, title)
        clr_st(ctx)
        await update.message.reply_text(
            f"✅ <b>Channel Added to Force Join!</b>\n\n"
            f"🏷 <b>Button Title:</b> <code>{h(title)}</code>\n"
            f"📢 <b>Channel:</b> <code>{h(username)}</code>\n"
            f"🔗 <b>Link:</b> {h(link)}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Force Join", callback_data="adm_force_join", style="success")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_ban" and uid == OWNER_ID:
        try:
            target = int(text)
            ban_user(target)
            clr_st(ctx)
            try:
                await ctx.bot.send_message(
                    chat_id=target,
                    text=(
                        "<b>🚫 Access Revoked</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                        "<b>You have been banned from this bot.</b>\n\n"
                        "<b>All actions are now blocked. Contact the owner if you believe this is a mistake.</b>"
                    ),
                    parse_mode=ParseMode.HTML,
                )
            except Exception:
                pass
            _bu = get_user(target)
            _uname = f"@{h(_bu['username'])}" if _bu and _bu.get("username") else (h(_bu.get("first_name","")) if _bu else f"uid:{target}")
            await update.message.reply_text(
                (
                    "<b>🚫 User Banned</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"<b>👤 User:     {_uname}</b>\n"
                    f"<b>🆔 User ID:  {target}</b>\n"
                    "<b>📊 Status:   Banned</b>\n\n"
                    "<b>They've been notified and blocked from all actions.</b>"
                ),
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
                parse_mode=ParseMode.HTML,
            )
        except ValueError:
            await update.message.reply_text("❌ Send a valid numeric User ID.", parse_mode=ParseMode.HTML)
        return

    if state == "adm_unban" and uid == OWNER_ID:
        try:
            target = int(text)
            unban_user(target)
            clr_st(ctx)
            try:
                await ctx.bot.send_message(
                    chat_id=target,
                    text=(
                        "<b>✅ Access Restored</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                        "<b>You have been unbanned from this bot.</b>\n\n"
                        "<b>Welcome back — you can use the bot again.</b>"
                    ),
                    parse_mode=ParseMode.HTML,
                )
            except Exception:
                pass
            _bu = get_user(target)
            _uname = f"@{h(_bu['username'])}" if _bu and _bu.get("username") else (h(_bu.get("first_name","")) if _bu else f"uid:{target}")
            await update.message.reply_text(
                (
                    "<b>✅ User Unbanned</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"<b>👤 User:     {_uname}</b>\n"
                    f"<b>🆔 User ID:  {target}</b>\n"
                    "<b>📊 Status:   Active</b>\n\n"
                    "<b>Access has been restored.</b>"
                ),
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
                parse_mode=ParseMode.HTML,
            )
        except ValueError:
            await update.message.reply_text("❌ Send a valid numeric User ID.", parse_mode=ParseMode.HTML)
        return

    if state == "adm_transfer_bot" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ Send the new owner's User ID.", parse_mode=ParseMode.HTML)
            return
        bid = ctx.user_data.get("transfer_bid","")
        try:
            new_uid = int(text.strip())
        except ValueError:
            await update.message.reply_text("❌ Send a valid numeric User ID.", parse_mode=ParseMode.HTML)
            return
        b = get_bot(bid)
        if not b:
            clr_st(ctx)
            await update.message.reply_text("❌ Bot not found.", parse_mode=ParseMode.HTML)
            return
        ok, msg = transfer_bot_ownership(bid, new_uid)
        clr_st(ctx)
        if ok:
            await update.message.reply_text(
                f"✅ <b>Bot Transferred!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"📄 <b>Bot:</b> <code>{h(b.get('file_name',''))}</code>\n"
                f"👤 <b>New Owner:</b> <code>{new_uid}</code>",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
                parse_mode=ParseMode.HTML,
            )
        else:
            await update.message.reply_text(
                f"❌ <b>Transfer Failed:</b> {h(msg)}",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
                parse_mode=ParseMode.HTML,
            )
        return

    if state == "user_transfer_bot":
        if not text:
            await update.message.reply_text("❌ Send the new owner's User ID.", parse_mode=ParseMode.HTML)
            return
        bid = ctx.user_data.get("transfer_bid","")
        b = get_bot(bid)
        if not b or b["user_id"] != uid:
            clr_st(ctx)
            await update.message.reply_text("❌ Bot not found.", reply_markup=kb_back("mybots"), parse_mode=ParseMode.HTML)
            return
        try:
            new_uid = int(text.strip())
        except ValueError:
            await update.message.reply_text("❌ Send a valid numeric User ID.", parse_mode=ParseMode.HTML)
            return
        ok, msg = transfer_bot_ownership(bid, new_uid)
        clr_st(ctx)
        if ok:
            await update.message.reply_text(
                f"✅ <b>Bot Transferred!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"📄 <b>Bot:</b> <code>{h(b.get('file_name',''))}</code>\n"
                f"👤 <b>New Owner:</b> <code>{new_uid}</code>\n\n"
                f"<b>The bot has been removed from your account.</b>",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🤖 My Bots", callback_data="mybots", style="primary")],
                    [InlineKeyboardButton("🏠 Home", callback_data="home", style="primary")],
                ]),
                parse_mode=ParseMode.HTML,
            )
        else:
            await update.message.reply_text(
                f"❌ <b>Transfer Failed:</b> {h(msg)}",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 My Bots", callback_data="mybots", style="primary")]]),
                parse_mode=ParseMode.HTML,
            )
        return

    if state == "adm_del_msg_fwd" and uid == OWNER_ID:
        msg = update.message
        clr_st(ctx)
        fwd_msg_id = None
        origin = getattr(msg,"forward_origin",None)
        if origin:
            fwd_msg_id = getattr(origin,"message_id",None)
        if not fwd_msg_id:
            fwd_msg_id = getattr(msg,"forward_from_message_id",None)
        fwd_text_content = (msg.text or msg.caption or "").strip()
        if not fwd_msg_id and not fwd_text_content:
            await update.message.reply_text(
                "❌ <b>Could not read the original message.</b>",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
                parse_mode=ParseMode.HTML,
            )
            return
        found_record   = None
        found_sent_map = None
        found_preview  = ""
        try:
            fwd_int = int(fwd_msg_id) if fwd_msg_id else None
        except (TypeError, ValueError):
            fwd_int = None
        fwd_str = str(fwd_msg_id) if fwd_msg_id else ""
        for bc in all_broadcasts():
            sm = bc.get("sent_map",{})
            vals_str = [str(v) for v in sm.values()]
            if (fwd_int is not None and fwd_int in sm.values()) or (fwd_str and fwd_str in vals_str):
                found_record   = bc["id"]
                found_sent_map = sm
                found_preview  = bc.get("preview","")[:60]
                break
        if not found_record:
            for cm in all_custom_messages():
                sm = cm.get("chat_map",{})
                vals_str = [str(v) for v in sm.values()]
                if (fwd_int is not None and fwd_int in sm.values()) or (fwd_str and fwd_str in vals_str):
                    found_record   = cm["id"]
                    found_sent_map = sm
                    found_preview  = cm.get("preview","")[:60]
                    break
        if not found_record:
            if not fwd_msg_id:
                await update.message.reply_text(
                    "❌ <b>Message not found in records.</b>",
                    reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
                    parse_mode=ParseMode.HTML,
                )
                return
            await update.message.reply_text(
                f"⚠️ <b>Message not in records.</b>\n\n🆔 <b>Detected ID:</b> <code>{fwd_msg_id}</code>\n\n<b>Try to delete anyway?</b>",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("✅ Yes, Try Delete", callback_data=f"adm_force_del_{fwd_msg_id}", style="danger"),
                     InlineKeyboardButton("❌ Cancel",          callback_data="adm_panel", style="danger")],
                ]), parse_mode=ParseMode.HTML,
            )
            return
        await update.message.reply_text(
            f"🗑️ <b>Message Found!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📝 <b>Preview:</b> {h(found_preview)}\n"
            f"👥 <b>Sent to:</b> <b>{len(found_sent_map)}</b> users\n\n"
            f"<b>Delete from all users' chats?</b>",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("✅ Yes, Delete", callback_data=f"adm_delcm_confirm_{found_record}", style="success"),
                 InlineKeyboardButton("❌ No, Cancel",  callback_data="adm_panel", style="danger")],
            ]), parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_bb_msg" and uid == OWNER_ID:
        msg = update.message
        # text, sticker, animation/GIF, photo, video, voice, audio, document.
        _has_content = bool(
            msg.text or msg.sticker or msg.animation or msg.photo
            or msg.video or msg.voice or msg.audio or msg.document
            or msg.caption
        )
        if not _has_content:
            await msg.reply_text(
                "❌ <b>Send the content to broadcast via hosted bots.</b>\n\n"
                "<b>Supported: text (with Premium emoji), stickers, GIFs, "
                "photos, videos, voice, audio, documents.</b>",
                parse_mode=ParseMode.HTML,
            )
            return
        target = ctx.user_data.get("bb_target", "all")
        bb_bid = ctx.user_data.get("bb_bid", "")
        clr_st(ctx)
        if target == "one":
            b = get_bot(bb_bid)
            if not b:
                await msg.reply_text("❌ <b>Bot not found.</b>", reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML)
                return
            tok = get_decrypted_bot_token(b) or extract_bot_token(b.get("file_path", ""))
            if not tok:
                await msg.reply_text("❌ <b>No token found in this bot's file.</b>", reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML)
                return
            info = hosted_bot_get_me(tok) or {}
            live_users = fetch_hosted_bot_users_from_updates(tok)
            if live_users:
                add_hosted_bot_users_bulk(tok, live_users)
            bot_owner_ids = {str(bv["user_id"]) for bv in all_bots().values() if bv.get("user_id")}
            recipients = [u for u in hosted_bot_users_list(tok) if str(u) not in bot_owner_ids]
            chosen = [{"bid": bb_bid, "token": tok,
                       "username": info.get("username", ""),
                       "name": info.get("first_name") or b.get("file_name", "bot"),
                       "recipients": recipients}]
        else:
            chosen = _bb_pickable_bots()
            if not chosen:
                await msg.reply_text("❌ <b>No hosted bots with readable tokens found.</b>", reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML)
                return
            bot_owner_ids = {str(bv["user_id"]) for bv in all_bots().values() if bv.get("user_id")}
            for c in chosen:
                live = fetch_hosted_bot_users_from_updates(c["token"])
                if live:
                    add_hosted_bot_users_bulk(c["token"], live)
                c["recipients"] = [u for u in hosted_bot_users_list(c["token"]) if str(u) not in bot_owner_ids]

        total_recipients = sum(len(c.get("recipients", [])) for c in chosen)
        _bb_preview = (msg.text or msg.caption or "")[:60]
        if not _bb_preview:
            if msg.sticker:
                _bb_preview = f"[Sticker: {msg.sticker.emoji or ''}]"
            elif msg.animation:
                _bb_preview = "[GIF/Animation]"
            elif msg.photo:
                _bb_preview = "[Photo]"
            elif msg.video:
                _bb_preview = "[Video]"
            elif msg.voice:
                _bb_preview = "[Voice]"
            elif msg.audio:
                _bb_preview = "[Audio]"
            elif msg.document:
                _bb_preview = f"[Document: {(msg.document.file_name or '')}]"
            else:
                _bb_preview = "[Media]"
        pm = await msg.reply_text(
            f"⏳ <b>Broadcasting via {len(chosen)} bot(s) to ~{total_recipients} user(s)…</b>\n"
            f"<b>Content: {h(_bb_preview)}</b>",
            parse_mode=ParseMode.HTML,
        )
        per_bot_stats = []
        grand_sent = grand_failed = 0
        for entry in chosen:
            ok = fail = 0
            tok = entry["token"]
            recipients = entry.get("recipients", [])
            for u_id in recipients:
                try:
                    sent_ok, _mid = hosted_bot_copy_msg(tok, int(u_id), msg)
                    if sent_ok:
                        ok += 1
                    else:
                        fail += 1
                except Exception:
                    fail += 1
                await asyncio.sleep(0.05)
            label = f"@{entry['username']}" if entry.get("username") else entry.get("name", "bot")
            per_bot_stats.append(f"• {h(label)} — ✅ <b>{ok}</b>  ❌ <b>{fail}</b>  👥 {len(recipients)}")
            grand_sent   += ok
            grand_failed += fail

        summary = "\n".join(per_bot_stats[:20])
        await pm.edit_text(
            f"📡 <b>Bot Broadcast Complete!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"🤖 <b>Bots:</b> <b>{len(chosen)}</b>\n"
            f"👥 <b>Total recipients:</b> <b>{total_recipients}</b>\n"
            f"✅ <b>Sent:</b>   <b>{grand_sent}</b>\n"
            f"❌ <b>Failed:</b> <b>{grand_failed}</b>\n\n"
            f"<b>Per bot:</b>\n{summary}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_broadcast" and uid == OWNER_ID:
        msg = update.message
        bans = set(str(b) for b in _load().get("bans",[]))
        recipient_count = sum(1 for u in all_users().keys() if str(u) not in bans)
        if recipient_count == 0:
            clr_st(ctx)
            await update.message.reply_text("⚠️ <b>No recipients.</b>", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]), parse_mode=ParseMode.HTML)
            return
        preview_src = (msg.text or msg.caption or "")
        preview = preview_src[:80] + ("…" if len(preview_src) > 80 else "") or "[media]"
        set_st(ctx, "adm_broadcast_confirm", bc_from_chat=msg.chat_id, bc_msg_id=msg.message_id, bc_preview=preview)
        await update.message.reply_text(
            f"✉️ <b>Confirm Broadcast?</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📝 <b>Preview:</b> {h(preview)}\n"
            f"👥 <b>Recipients:</b> <b>{recipient_count}</b>\n\n"
            f"<b>Send to all?</b>",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("✅ Yes, Send",   callback_data="adm_bc_send", style="primary"),
                 InlineKeyboardButton("❌ No, Cancel",  callback_data="adm_bc_cancel", style="danger")],
            ]), parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_code_days" and uid == OWNER_ID:
        try:
            days = int(text)
            if days < 1:
                raise ValueError
        except ValueError:
            await update.message.reply_text("❌ Send a valid number of days.", parse_mode=ParseMode.HTML)
            return
        plan = ctx.user_data.get("code_plan","basic")
        if plan not in PLANS:
            plan = "basic"
        set_st(ctx, "adm_code_max_uses", code_plan=plan, code_days=days)
        pl = PLANS[plan]
        await update.message.reply_text(
            f"💎 <b>{pl['emoji']} {pl['name']}</b> — <b>{days} days</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"<b>Step 3:</b> Max uses per code?\n<b>Send a number (e.g. <code>1</code> for single use)</b>",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_code_max_uses" and uid == OWNER_ID:
        try:
            max_uses = int(text)
            if max_uses < 1:
                raise ValueError
        except ValueError:
            await update.message.reply_text("❌ Send a valid number (e.g. 1).", parse_mode=ParseMode.HTML)
            return
        plan = ctx.user_data.get("code_plan","basic")
        days = ctx.user_data.get("code_days",30)
        if plan not in PLANS:
            plan = "basic"
        set_st(ctx, "adm_code_choose_type", code_plan=plan, code_days=days, code_max_uses=max_uses)
        pl = PLANS[plan]
        await update.message.reply_text(
            f"💎 <b>{pl['emoji']} {pl['name']}</b> — <b>{days} days</b> — <b>{max_uses} uses</b>\n"
            f"┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n<b>Step 4:</b> Choose code type:",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("✏️ Custom Code",   callback_data="adm_code_do_custom", style="primary"),
                 InlineKeyboardButton("🎲 Auto-Generate", callback_data="adm_code_do_auto", style="primary")],
                [InlineKeyboardButton("❌ Cancel",         callback_data="adm_panel", style="danger")],
            ]), parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_code_enter_custom" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ <b>Send the code text.</b>", parse_mode=ParseMode.HTML)
            return
        custom = text.upper().strip()
        if not re.match(r"^[A-Z0-9\-]{3,30}$", custom):
            await update.message.reply_text("❌ <b>Invalid format.</b>\n3–30 chars: letters, numbers, hyphens.", parse_mode=ParseMode.HTML)
            return
        if code_exists(custom):
            await update.message.reply_text(f"❌ <code>{custom}</code> already exists.", parse_mode=ParseMode.HTML)
            return
        plan = ctx.user_data.get("code_plan","basic")
        days = ctx.user_data.get("code_days",30)
        max_uses = ctx.user_data.get("code_max_uses",1)
        if plan not in PLANS:
            plan = "basic"
        save_code(custom, plan, days, max_uses)
        clr_st(ctx)
        pl = PLANS[plan]
        duration_display = "Lifetime ♾️" if plan == "lifetime" else f"{days} days"
        await update.message.reply_text(
            f"✅ <b>Custom Code Created!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"🎫 <b>Code:</b>     <code>{custom}</code>\n"
            f"{pl['emoji']} <b>Plan:</b>     <b>{pl['name']}</b>\n"
            f"📅 <b>Duration:</b> <b>{duration_display}</b>\n"
            f"👥 <b>Max Uses:</b> <b>{max_uses}</b>",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_givesub_uid" and uid == OWNER_ID:
        try:
            target_uid = int(text)
        except ValueError:
            await update.message.reply_text("❌ Send a valid numeric User ID.", parse_mode=ParseMode.HTML)
            return
        u = get_user(target_uid)
        if not u:
            await update.message.reply_text(
                f"❌ User <code>{target_uid}</code> not found in database.",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
                parse_mode=ParseMode.HTML,
            )
            clr_st(ctx)
            return
        clr_st(ctx)
        await update.message.reply_text(
            f"🎁 <b>Give Subscription</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\nUser: <code>{target_uid}</code>\n\n<b>Select plan:</b>",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🍼 Baby",    callback_data=f"adm_gsplan_baby_{target_uid}", style="primary"),
                 InlineKeyboardButton("⭐ Basic",   callback_data=f"adm_gsplan_basic_{target_uid}", style="primary")],
                [InlineKeyboardButton("💎 Premium", callback_data=f"adm_gsplan_premium_{target_uid}", style="primary"),
                 InlineKeyboardButton("⚡ God",     callback_data=f"adm_gsplan_god_{target_uid}", style="primary")],
                [InlineKeyboardButton("👑 Ultimate",callback_data=f"adm_gsplan_ultimate_{target_uid}", style="primary"),
                 InlineKeyboardButton("♾️ Lifetime",callback_data=f"adm_gsplan_lifetime_{target_uid}", style="primary")],
                [InlineKeyboardButton("🆓 Reset Free",callback_data=f"adm_gsplan_free_{target_uid}", style="primary")],
                [InlineKeyboardButton("❌ Cancel",   callback_data="adm_panel", style="danger")],
            ]), parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_gsub_days" and uid == OWNER_ID:
        try:
            days = int(text)
            if days < 1:
                raise ValueError
        except ValueError:
            await update.message.reply_text("❌ Send a valid number of days.", parse_mode=ParseMode.HTML)
            return
        plan    = ctx.user_data.get("gs_plan","basic")
        uid_s   = ctx.user_data.get("gs_uid","")
        if plan not in PLANS:
            plan = "basic"
        give_subscription(int(uid_s), plan, days)
        clr_st(ctx)
        pl = PLANS[plan]
        u = get_user(int(uid_s))
        username = (u.get("username") or uid_s) if u else uid_s
        duration_display = "Lifetime ♾️" if plan == "lifetime" else f"{days} days"
        try:
            await ctx.bot.send_message(
                chat_id=int(uid_s),
                text=(
                    f"🎉 <b>Subscription Granted!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"{pl['emoji']} <b>Plan:</b>     <b>{pl['name']}</b>\n"
                    f"📅 <b>Duration:</b> <b>{duration_display}</b>\n\n"
                    f"<b>Enjoy your premium hosting! 🚀</b>"
                ),
                reply_markup=kb_main(),
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
        await update.message.reply_text(
            f"✅ <b>Subscription Given!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"👤 User: <code>{uid_s}</code> (@{h(str(username))})\n"
            f"{pl['emoji']} <b>Plan:</b>     <b>{pl['name']}</b>\n"
            f"📅 <b>Duration:</b> <b>{duration_display}</b>",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 User Profile", callback_data=f"adm_user_{uid_s}", style="primary"),
                 InlineKeyboardButton("👥 All Users",    callback_data="adm_users", style="primary")],
                [InlineKeyboardButton("🔙 Admin Panel",  callback_data="adm_panel", style="primary")],
            ]), parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_customram_uid" and uid == OWNER_ID:
        try:
            target_uid = int(text)
        except ValueError:
            await update.message.reply_text("❌ Send a valid numeric User ID.", parse_mode=ParseMode.HTML)
            return
        u = get_user(target_uid)
        if not u:
            await update.message.reply_text(
                f"❌ User <code>{target_uid}</code> not found in database.",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
                parse_mode=ParseMode.HTML,
            )
            clr_st(ctx)
            return
        current_plan = PLANS.get(u.get("plan","free"), PLANS["free"])
        current_custom = u.get("custom_ram_mb")
        current_str = f"{current_custom} MB (custom)" if current_custom else f"{current_plan.get('ram_mb','?')} MB (plan default)"
        set_st(ctx, "adm_customram_value", cram_uid=target_uid)
        await update.message.reply_text(
            f"🧠 <b>Custom RAM Allowance</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"User: <code>{target_uid}</code>\n"
            f"Plan: {current_plan.get('emoji','')} {current_plan.get('name','Free')}\n"
            f"Current RAM: <b>{current_str}</b>\n\n"
            f"<b>Step 2:</b> Send the new RAM limit for this user\n"
            f"<b>e.g. <code>512mb</code>, <code>2gb</code>, or a plain number in MB like <code>768</code></b>",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="adm_panel", style="danger")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_customram_value" and uid == OWNER_ID:
        target_uid = ctx.user_data.get("cram_uid")
        raw = text.strip().lower().replace(" ", "")
        m = re.match(r"^(\d+(?:\.\d+)?)(mb|gb|m|g)?$", raw)
        if not m or not target_uid:
            await update.message.reply_text(
                "❌ Invalid format. Send e.g. <code>512mb</code>, <code>2gb</code>, or <code>768</code>.",
                parse_mode=ParseMode.HTML,
            )
            return
        amount = float(m.group(1))
        unit = m.group(2) or "mb"
        ram_mb = int(round(amount * 1024)) if unit in ("gb", "g") else int(round(amount))
        if ram_mb < 32:
            await update.message.reply_text("❌ RAM must be at least 32 MB.", parse_mode=ParseMode.HTML)
            return
        upd_user(target_uid, {"custom_ram_mb": ram_mb})
        clr_st(ctx)
        u = get_user(target_uid)
        username = (u.get("username") or str(target_uid)) if u else str(target_uid)
        try:
            await ctx.bot.send_message(
                chat_id=target_uid,
                text=(
                    f"📢 <b>RAM Allowance Updated</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                    f"🧠 <b>New RAM Limit:</b> <b>{ram_mb} MB</b>\n\n"
                    f"<b>This applies to your hosted bots regardless of your current plan.</b>"
                ),
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
        await update.message.reply_text(
            f"✅ <b>Custom RAM Assigned!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"👤 User: <code>{target_uid}</code> (@{h(str(username))})\n"
            f"🧠 <b>RAM Limit:</b> <b>{ram_mb} MB</b>\n"
            f"<b>Overrides plan default, including Free.</b>",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔙 User Profile", callback_data=f"adm_user_{target_uid}", style="primary"),
                 InlineKeyboardButton("👥 All Users",    callback_data="adm_users", style="primary")],
                [InlineKeyboardButton("🔙 Admin Panel",  callback_data="adm_panel", style="primary")],
            ]), parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_add_users" and uid == OWNER_ID:
        if doc and doc.file_name and doc.file_name.endswith(".txt"):
            pm = await update.message.reply_text("⏳ <b>Processing txt file…</b>", parse_mode=ParseMode.HTML)
            tg_file = await ctx.bot.get_file(doc.file_id)
            tmp_path = os.path.join(BASE_DIR, f"tmp_addusers_{uuid.uuid4().hex}.txt")
            await tg_file.download_to_drive(tmp_path)
            try:
                with open(tmp_path,"r",encoding="utf-8",errors="ignore") as f:
                    raw_content = f.read()
                os.remove(tmp_path)
            except Exception:
                raw_content = ""
            raw_ids = re.split(r"[\s,\n]+", raw_content.strip())
        elif text:
            pm = await update.message.reply_text("⏳ <b>Processing…</b>", parse_mode=ParseMode.HTML)
            raw_ids = re.split(r"[\s,\n]+", text.strip())
        else:
            await update.message.reply_text("❌ <b>Send User ID(s) or a .txt file.</b>", parse_mode=ParseMode.HTML)
            return
        results = []
        added = already = failed = 0
        for raw in raw_ids:
            raw = raw.strip()
            if not raw or not raw.isdigit():
                continue
            try:
                t_uid = int(raw)
            except ValueError:
                failed += 1
                continue
            existing = get_user(t_uid)
            if existing:
                already += 1
                results.append(f"✅ <code>{t_uid}</code> — already (@{h(existing.get('username') or 'N/A')}, {existing.get('plan','free')})")
                continue
            fetched_username = ""
            fetched_name = ""
            try:
                chat = await ctx.bot.get_chat(t_uid)
                fetched_username = getattr(chat,"username","") or ""
                fetched_name = getattr(chat,"first_name","") or ""
            except Exception:
                pass
            ensure_user(t_uid, fetched_username, fetched_name)
            added += 1
            tag = f"@{fetched_username}" if fetched_username else f"({fetched_name or 'unknown'})"
            results.append(f"➕ <code>{t_uid}</code> — added {h(tag)}")
        clr_st(ctx)
        summary = "\n".join(results[:30])
        if len(results) > 30:
            summary += f"\n<b>…and {len(results)-30} more</b>"
        await pm.edit_text(
            f"➕ <b>Add Users Result</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"✅ <b>Added:</b> <b>{added}</b>  •  <b>Already:</b> <b>{already}</b>  •  ❌ <b>Failed:</b> <b>{failed}</b>\n\n"
            f"{summary}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "adm_delete_users" and uid == OWNER_ID:
        if doc and doc.file_name and doc.file_name.endswith(".txt"):
            pm = await update.message.reply_text("⏳ <b>Processing txt file…</b>", parse_mode=ParseMode.HTML)
            tg_file = await ctx.bot.get_file(doc.file_id)
            tmp_path = os.path.join(BASE_DIR, f"tmp_delusers_{uuid.uuid4().hex}.txt")
            await tg_file.download_to_drive(tmp_path)
            try:
                with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw_content = f.read()
                os.remove(tmp_path)
            except Exception:
                raw_content = ""
            raw_ids = re.split(r"[\s,\n]+", raw_content.strip())
        elif text:
            pm = await update.message.reply_text("⏳ <b>Processing…</b>", parse_mode=ParseMode.HTML)
            raw_ids = re.split(r"[\s,\n]+", text.strip())
        else:
            await update.message.reply_text("❌ <b>Send User ID(s) or a .txt file.</b>", parse_mode=ParseMode.HTML)
            return
        deleted = skipped = failed = 0
        results = []
        for raw in raw_ids:
            raw = raw.strip()
            if not raw or not raw.isdigit():
                continue
            try:
                t_uid = int(raw)
            except ValueError:
                failed += 1
                continue
            existing = get_user(t_uid)
            if not existing:
                skipped += 1
                results.append(f"⚠️ <code>{t_uid}</code> — not found, skipped")
                continue
            uname = existing.get("username") or ""
            fname = existing.get("first_name") or existing.get("name") or ""
            tag = f"@{uname}" if uname else (f"({fname})" if fname else "")
            del_user(t_uid)
            deleted += 1
            results.append(f"🗑️ <code>{t_uid}</code> {h(tag)} — deleted")
        clr_st(ctx)
        summary = "\n".join(results[:30])
        if len(results) > 30:
            summary += f"\n<b>…and {len(results)-30} more</b>"
        await pm.edit_text(
            f"🗑️ <b>Delete Users Result</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"✅ <b>Deleted:</b> <b>{deleted}</b>  •  ⚠️ <b>Not found:</b> <b>{skipped}</b>  •  ❌ <b>Failed:</b> <b>{failed}</b>\n\n"
            f"{summary}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "awaiting_restore_backup_file" and uid == OWNER_ID:
        if not doc:
            await update.message.reply_text(
                "❌ <b>Please send the backup .txt file.</b>\n"
                "<b>Forward it from the backup channel or upload it directly.</b>",
                parse_mode=ParseMode.HTML,
            )
            return
        await _do_restore_from_doc(update, ctx, doc)
        return

    if state == "adm_upload_backup_file" and uid == OWNER_ID:
        if not doc:
            await update.message.reply_text(
                "❌ <b>Please send the backup <code>.zip</code> file.</b>\n"
                "<b>Forward it or upload it directly.</b>",
                parse_mode=ParseMode.HTML,
            )
            return
        await _do_upload_backup_restore(update, ctx, doc)
        return

    if state == "adm_replace_file_upload" and uid == OWNER_ID:
        if not doc:
            await update.message.reply_text("❌ <b>Send the replacement file.</b>", parse_mode=ParseMode.HTML)
            return
        bid = ctx.user_data.get("replace_bid","")
        b = get_bot(bid)
        if not b:
            clr_st(ctx)
            await update.message.reply_text("❌ <b>Bot not found.</b>", reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML)
            return
        if not doc.file_name or not is_allowed_file(doc.file_name):
            await update.message.reply_text("❌ <b>Only .py files are accepted.</b>", parse_mode=ParseMode.HTML)
            return
        if doc.file_size > MAX_BYTES:
            await update.message.reply_text(f"❌ <b>File too large!</b> Max 25 MB.", parse_mode=ParseMode.HTML)
            return
        pm = await update.message.reply_text("⏳ <b>Replacing file…</b>", parse_mode=ParseMode.HTML)

        # Download to a temp path first and check for a bot token BEFORE
        # touching the existing working file — if the new file has no
        # token (and the bot has none on record either), reject it and
        # leave the currently-running bot completely untouched.
        tmp_check_fp = os.path.join(BACKUP_DIR, f".replace_check_{uuid.uuid4().hex}_{safe_filename(doc.file_name)}")
        os.makedirs(BACKUP_DIR, exist_ok=True)
        tg_file = await ctx.bot.get_file(doc.file_id)
        await tg_file.download_to_drive(tmp_check_fp)
        new_tok = extract_bot_token(tmp_check_fp) or get_decrypted_bot_token(b)
        if not new_tok:
            try:
                os.remove(tmp_check_fp)
            except Exception:
                pass
            clr_st(ctx)
            await pm.edit_text(
                "❌ <b>Bot Token Not Found</b>\n"
                "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                "🚫 <b>Bot Token Not Found In File.</b>\n"
                "📌 <b>Please Add Your Bot Token In The File First.</b>\n"
                "🔁 <b>Then Upload The File Again.</b>",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
                parse_mode=ParseMode.HTML,
            )
            return

        was_running = b.get("status") == "running"
        if was_running:
            proc_stop(bid)
        old_fp = b.get("file_path","")
        if old_fp and os.path.exists(old_fp):
            bk_dir = os.path.join(BACKUP_DIR, str(b["user_id"]))
            os.makedirs(bk_dir, exist_ok=True)
            try:
                shutil.copy2(old_fp, os.path.join(bk_dir, f"replaced_{b['file_name']}"))
            except Exception:
                pass
            os.remove(old_fp)
        new_name = safe_filename(doc.file_name)
        new_fp = os.path.join(os.path.dirname(old_fp), new_name) if old_fp else os.path.join(HOSTED_FILES_DIR, str(b["user_id"]), bid, safe_filename(doc.file_name))
        os.makedirs(os.path.dirname(new_fp), exist_ok=True)
        shutil.move(tmp_check_fp, new_fp)
        upd_bot(bid, {"file_path": new_fp, "file_name": doc.file_name, "bot_token": _encrypt_token(new_tok) if new_tok else ""})
        clr_st(ctx)
        if was_running:
            ok, msg = await asyncio.get_running_loop().run_in_executor(None, proc_start, bid)
            status_msg = f"✅ <b>File replaced &amp; bot restarted!</b>" if ok else f"⚠️ <b>File replaced, but bot failed to restart:</b>\n{msg}"
        else:
            status_msg = "✅ <b>File replaced successfully!</b>"
        await pm.edit_text(
            f"{status_msg}\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
            f"📄 <b>New file:</b> <code>{h(doc.file_name)}</code>",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")]]),
            parse_mode=ParseMode.HTML,
        )
        return

    if state == "user_replace_file_upload":
        if not doc:
            await update.message.reply_text("❌ <b>Send the replacement file.</b>", parse_mode=ParseMode.HTML)
            return
        bid = ctx.user_data.get("replace_bid","")
        b = get_bot(bid)
        if not b or b["user_id"] != uid:
            clr_st(ctx)
            await update.message.reply_text("❌ <b>Bot not found.</b>", reply_markup=kb_back("mybots"), parse_mode=ParseMode.HTML)
            return
        if not doc.file_name or not is_allowed_file(doc.file_name):
            await update.message.reply_text("❌ <b>Only .py files are accepted.</b>", parse_mode=ParseMode.HTML)
            return
        if doc.file_size > MAX_BYTES:
            await update.message.reply_text(f"❌ <b>File too large!</b> Max 25 MB.", parse_mode=ParseMode.HTML)
            return
        pm = await update.message.reply_text("⏳ <b>Replacing file…</b>", parse_mode=ParseMode.HTML)

        # Download to a temp path first and check for a bot token BEFORE
        # touching the existing working file — reject up front if no token
        # is present anywhere (and the bot has none on record either), so
        # the user's currently-working bot is never disturbed.
        tmp_check_fp = os.path.join(BACKUP_DIR, f".replace_check_{uuid.uuid4().hex}_{safe_filename(doc.file_name)}")
        os.makedirs(BACKUP_DIR, exist_ok=True)
        tg_file = await ctx.bot.get_file(doc.file_id)
        await tg_file.download_to_drive(tmp_check_fp)
        new_tok = extract_bot_token(tmp_check_fp) or get_decrypted_bot_token(b)
        if not new_tok:
            try:
                os.remove(tmp_check_fp)
            except Exception:
                pass
            clr_st(ctx)
            await pm.edit_text(
                "❌ <b>Bot Token Not Found</b>\n"
                "┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                "🚫 <b>Bot Token Not Found In File.</b>\n"
                "📌 <b>Please Add Your Bot Token In The File First.</b>\n"
                "🔁 <b>Then Upload The File Again.</b>",
                reply_markup=kb_main(),
                parse_mode=ParseMode.HTML,
            )
            return

        was_running = b.get("status") == "running"
        if was_running:
            proc_stop(bid)
        old_fp = b.get("file_path","")
        if old_fp and os.path.exists(old_fp):
            bk_dir = os.path.join(BACKUP_DIR, str(uid))
            os.makedirs(bk_dir, exist_ok=True)
            try:
                shutil.copy2(old_fp, os.path.join(bk_dir, f"replaced_{b['file_name']}"))
            except Exception:
                pass
            os.remove(old_fp)
        new_name = safe_filename(doc.file_name)
        new_fp = os.path.join(os.path.dirname(old_fp), new_name) if old_fp else os.path.join(HOSTED_FILES_DIR, str(uid), bid, new_name)
        os.makedirs(os.path.dirname(new_fp), exist_ok=True)
        shutil.move(tmp_check_fp, new_fp)
        clr_st(ctx)
        if needs_approval(uid):
            upd_bot(bid, {"file_path": new_fp, "file_name": doc.file_name,
                          "bot_token": _encrypt_token(new_tok) if new_tok else "",
                          "pending": True, "status": "stopped"})
            try:
                auto_username = await auto_fetch_bot_username(new_tok)
                await _notify_owner_pending(update, ctx, uid, bid, new_fp, doc.file_name, auto_username)
            except Exception:
                pass
            await pm.edit_text(
                f"⏳ <b>File Submitted for Approval</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"📄 <b>New file:</b> <code>{h(doc.file_name)}</code>\n\n"
                f"<b>Your replacement file is pending admin approval.\n"
                f"Your bot will restart automatically once approved.</b>",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 My Bots", callback_data="mybots", style="primary")]]),
                parse_mode=ParseMode.HTML,
            )
        else:
            upd_bot(bid, {"file_path": new_fp, "file_name": doc.file_name,
                          "bot_token": _encrypt_token(new_tok) if new_tok else ""})
            try:
                await _notify_owner_upload_viewonly(ctx, uid, bid, new_fp, doc.file_name, update.effective_user, label="🔁 <b>File Replaced</b>")
            except Exception:
                pass
            if was_running:
                ok, msg_r = await asyncio.get_running_loop().run_in_executor(None, proc_start, bid)
                status_msg = "✅ <b>File replaced &amp; bot restarted!</b>" if ok else f"⚠️ <b>File replaced, but bot failed to restart:</b>\n{msg_r}"
            else:
                status_msg = "✅ <b>File replaced successfully!</b>"
            await pm.edit_text(
                f"{status_msg}\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"📄 <b>New file:</b> <code>{h(doc.file_name)}</code>",
                reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 My Bots", callback_data="mybots", style="primary")]]),
                parse_mode=ParseMode.HTML,
            )
        return

    if state == "adm_github_url" and uid == OWNER_ID:
        if not text:
            await update.message.reply_text("❌ Send a URL.", parse_mode=ParseMode.HTML)
            return
        url = text.strip()
        url = re.sub(r"github\.com/([^/]+)/([^/]+)/blob/", r"raw.githubusercontent.com/\1/\2/", url)
        if not url.startswith("http"):
            await update.message.reply_text("❌ Send a valid URL starting with http.", parse_mode=ParseMode.HTML)
            return
        pm = await update.message.reply_text(f"⏳ <b>Downloading from GitHub…</b>\n<code>{h(url)}</code>", parse_mode=ParseMode.HTML)
        clr_st(ctx)
        try:
            req = _urlreq.Request(url, headers={"User-Agent":"Mozilla/5.0"})
            with _urlreq.urlopen(req, timeout=30) as r:
                content = r.read()
            fname = url.split("/")[-1].split("?")[0] or "imported_bot.py"
            fname = safe_filename(fname)
            ext = file_ext(fname)
            if ext not in ALLOWED_EXTENSIONS:
                await pm.edit_text(
                    f"❌ <b>File type not allowed:</b> <code>{h(ext)}</code>",
                    reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
                )
                return
            bot_dir = os.path.join(HOSTED_FILES_DIR, str(uid), str(uuid.uuid4())[:8])
            os.makedirs(bot_dir, exist_ok=True)
            save_fp = os.path.join(bot_dir, fname)
            with open(save_fp,"wb") as f:
                f.write(content)
            bid2 = os.path.basename(bot_dir)
            bot_tok = extract_bot_token(save_fp) or ""
            add_bot(uid, bid2, fname, save_fp, pending=False, bot_token=bot_tok)
            if bot_tok:
                add_hosted_bot_users_bulk(bot_tok,[])
            await pm.edit_text(
                f"✅ <b>GitHub Import Successful!</b>\n┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈\n"
                f"📄 <b>File:</b> <code>{h(fname)}</code>\n"
                f"🆔 <b>Bot ID:</b> <code>{bid2}</code>\n"
                f"📦 <b>Size:</b> {len(content)/1024:.1f} KB",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("▶️ Start Now", callback_data=f"bact_start_{bid2}", style="success"),
                     InlineKeyboardButton("🤖 My Bots",   callback_data="mybots", style="primary")],
                    [InlineKeyboardButton("🔙 Back", callback_data="adm_panel", style="primary")],
                ]), parse_mode=ParseMode.HTML,
            )
        except Exception as e:
            await pm.edit_text(
                f"❌ <b>GitHub Import Failed</b>\n\n<code>{h(e)}</code>",
                reply_markup=kb_back("adm_panel"), parse_mode=ParseMode.HTML,
            )
        return

        return

    await update.message.reply_text(
        "👋 <b>Use /start to open the menu.</b>",
        reply_markup=kb_main(), parse_mode=ParseMode.HTML,
    )

#  LIVE LOG STREAMING

_live_log_tasks: dict = {}

async def _live_log_stream(bot, chat_id: int, message_id: int, bid: str, duration: int = 90):
    stop_kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("⏹ Stop Live Logs", callback_data=f"bact_stoplive_{bid}", style="danger")],
        [InlineKeyboardButton("🔙 Back",           callback_data=f"bot_{bid}", style="primary")],
    ])
    elapsed = 0
    last_body = ""
    while elapsed < duration:
        await asyncio.sleep(3)
        elapsed += 3
        try:
            lp = _log_path(bid)
            if not os.path.exists(lp):
                body = "(No logs yet)"
            else:
                with open(lp, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                tail = lines[-40:] if len(lines) > 40 else lines
                body = "".join(tail).strip() or "(Log file is empty)"
            if body == last_body:
                continue
            last_body = body
            body_safe = md2_code_escape(body)
            if len(body_safe) > 3200:
                body_safe = "…\\(truncated\\)\n" + body_safe[-3200:]
            remaining = duration - elapsed
            bcur = get_bot(bid)
            bname = bcur.get("file_name", bid) if bcur else bid
            status_line = _status_dot_plain(bcur.get("status", "") if bcur else "")
            header = (
                f"📡 *Live Logs — {md2_escape(bname)}*\n"
                f"{md2_escape(status_line)}  •  ⏳ {md2_escape(f'{remaining}s left')}\n"
                f"{md2_escape('┈' * 24)}"
            )
            text = f"{header}\n```\n{body_safe}\n```"
            await bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_id,
                text=text,
                reply_markup=stop_kb,
                parse_mode=ParseMode.MARKDOWN_V2,
            )
        except asyncio.CancelledError:
            break
        except Exception:
            pass

    try:
        logs_md = format_logs_md2(bid)
        await bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text=logs_md,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄 Refresh",    callback_data=f"bact_logs_{bid}", style="primary"),
                 InlineKeyboardButton("📡 Live Logs", callback_data=f"bact_livelogs_{bid}", style="primary")],
                [InlineKeyboardButton("🔙 Back",       callback_data=f"bot_{bid}", style="primary")],
            ]),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
    except Exception:
        pass
    _live_log_tasks.pop(bid, None)


async def cb_live_logs(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    bid = q.data.split("bact_livelogs_", 1)[1]
    b = get_bot(bid)
    if not b:
        await q.answer("❌ Bot not found.", show_alert=True)
        return
    await q.answer("📡 Starting live log stream…")

    old = _live_log_tasks.pop(bid, None)
    if old and not old.done():
        old.cancel()

    try:
        logs_md = format_logs_md2(bid)
        stop_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⏹ Stop Live Logs", callback_data=f"bact_stoplive_{bid}", style="danger")],
            [InlineKeyboardButton("🔙 Back",           callback_data=f"bot_{bid}", style="primary")],
        ])
        msg = await q.edit_message_text(
            logs_md,
            reply_markup=stop_kb,
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        message_id = msg.message_id if hasattr(msg, "message_id") else q.message.message_id
    except Exception:
        message_id = q.message.message_id

    task = asyncio.create_task(
        _live_log_stream(ctx.bot, q.message.chat_id, message_id, bid, duration=90)
    )
    _live_log_tasks[bid] = task


async def cb_stop_live_logs(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer("⏹ Live log stream stopped.")
    bid = q.data.split("bact_stoplive_", 1)[1]
    old = _live_log_tasks.pop(bid, None)
    if old and not old.done():
        old.cancel()
    try:
        logs_md = format_logs_md2(bid)
        await q.edit_message_text(
            logs_md,
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄 Refresh",    callback_data=f"bact_logs_{bid}", style="primary"),
                 InlineKeyboardButton("📡 Live Logs", callback_data=f"bact_livelogs_{bid}", style="primary")],
                [InlineKeyboardButton("🔙 Back",       callback_data=f"bot_{bid}", style="primary")],
            ]),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
    except Exception:
        pass


#  ERROR HANDLER

async def on_error(update: object, ctx: ContextTypes.DEFAULT_TYPE):
    err = ctx.error
    if isinstance(err, (TimedOut, NetworkError)):
        return
    if isinstance(err, RetryAfter):
        return
    if isinstance(err, Forbidden):
        # Bot was blocked by user or kicked from chat — ignore silently
        return
    if isinstance(err, BadRequest):
        msg = str(err).lower()
        # Ignore known harmless Telegram API edge-cases
        harmless = [
            "not modified",
            "query is too old",
            "query id is invalid",
            "message is not modified",
            "message to delete not found",
            "message to edit not found",
            "message can't be deleted",
            "have no rights to send a message",
            "bot was blocked by the user",
            "user is deactivated",
            "chat not found",
            "bot is not a member",
            "wrong type of the web page content",
        ]
        if any(x in msg for x in harmless):
            return
        # Log but don't crash for other bad requests
        log.warning("BadRequest in handler: %s", err)
        if isinstance(update, Update):
            try:
                if update.callback_query:
                    try:
                        await update.callback_query.answer(
                            "⚠️ Action failed. Please go back and try again.",
                            show_alert=False,
                        )
                    except Exception:
                        pass
                elif update.message:
                    await update.message.reply_text(
                        "⚠️ <b>Something went wrong.</b> Please try again.",
                        parse_mode=ParseMode.HTML,
                    )
            except Exception:
                pass
        return
    log.error("Unhandled exception in handler", exc_info=err)
    if isinstance(update, Update):
        try:
            if update.callback_query:
                try:
                    await update.callback_query.answer(
                        "⚠️ An error occurred. Please try again.",
                        show_alert=False,
                    )
                except Exception:
                    pass
                # Try to edit the message so it doesn't get stuck
                try:
                    await update.callback_query.edit_message_text(
                        "⚠️ <b>Something went wrong.</b> Please tap 🏠 Home to continue.",
                        reply_markup=InlineKeyboardMarkup([
                            [InlineKeyboardButton("🏠 Home", callback_data="home", style="primary")]
                        ]),
                        parse_mode=ParseMode.HTML,
                    )
                except Exception:
                    pass
            elif update.message:
                await update.message.reply_text(
                    "⚠️ <b>Something went wrong.</b> Please try again or use /start.",
                    reply_markup=kb_main(),
                    parse_mode=ParseMode.HTML,
                )
        except Exception:
            pass

#  MAIN

def main():
    _raise_host_rlimits()

    if not Bot_token or Bot_token == "YOUR_BOT_TOKEN_HERE":
        print("❌ No token set!\nSet BOT_TOKEN env var or paste token at top of file.")
        raise SystemExit(1)

    # separate per-bot files in HOSTED_BOT_USERS_DIR (runs instantly if already done)
    _hbu_migrate_from_db()

    threading.Thread(target=_pre_install_basic_packages, daemon=True).start()

    app = ApplicationBuilder().token(Bot_token).build()
    app.add_error_handler(on_error)

    app.add_handler(CommandHandler("start",          cmd_start))
    app.add_handler(CommandHandler("profile",        cmd_profile))
    app.add_handler(CommandHandler("admin_panel",    cmd_admin))
    app.add_handler(CommandHandler("logs",           cmd_logs))
    app.add_handler(CommandHandler("fetch_backup",   cmd_fetch_backup))
    app.add_handler(CommandHandler("restore_backup", cmd_restore_backup))

    app.add_handler(MessageHandler(filters.ALL & ~filters.COMMAND, on_message))

    app.add_handler(CallbackQueryHandler(cb_fj_verify,       pattern="^fj_verify$"))
    app.add_handler(CallbackQueryHandler(cb_home,            pattern="^home$"))
    app.add_handler(CallbackQueryHandler(cb_profile_refresh, pattern="^profile_refresh$"))
    app.add_handler(CallbackQueryHandler(cb_plans,           pattern="^plans$"))
    app.add_handler(CallbackQueryHandler(cb_plans_buy,       pattern="^plans_buy$"))
    app.add_handler(CallbackQueryHandler(cb_buy_plan,        pattern=r"^buy_plan_\w+$"))
    app.add_handler(CallbackQueryHandler(cb_redeem,          pattern="^redeem$"))
    app.add_handler(CallbackQueryHandler(cb_help,            pattern="^help$"))
    app.add_handler(CallbackQueryHandler(cb_bot_uptime,      pattern="^bot_uptime$"))
    app.add_handler(CallbackQueryHandler(cb_user_stats,      pattern="^user_stats$"))
    app.add_handler(CallbackQueryHandler(cb_pip_management,  pattern="^pip_management$"))
    app.add_handler(CallbackQueryHandler(cb_pip_install,     pattern="^pip_install$"))
    app.add_handler(CallbackQueryHandler(cb_pip_uninstall,   pattern="^pip_uninstall$"))
    app.add_handler(CallbackQueryHandler(cb_pip_error,       pattern="^pip_error$"))
    app.add_handler(CallbackQueryHandler(cb_upload,          pattern="^upload$"))
    app.add_handler(CallbackQueryHandler(cb_mybots,          pattern="^mybots$"))
    app.add_handler(CallbackQueryHandler(cb_bot_detail,      pattern=r"^bot_[a-z0-9]+$"))
    app.add_handler(CallbackQueryHandler(cb_bot_action,      pattern=r"^bact_(start|stop|restart|logs|delete|save|replace|transfer)_.+"))
    app.add_handler(CallbackQueryHandler(cb_live_logs,       pattern=r"^bact_livelogs_.+"))
    app.add_handler(CallbackQueryHandler(cb_stop_live_logs,  pattern=r"^bact_stoplive_.+"))

    app.add_handler(CallbackQueryHandler(cb_adm_panel,        pattern="^adm_panel$"))
    app.add_handler(CallbackQueryHandler(cb_adm_stats,        pattern="^adm_stats$"))
    app.add_handler(CallbackQueryHandler(cb_adm_bot_mgmt,     pattern="^adm_bot_mgmt$"))
    app.add_handler(CallbackQueryHandler(cb_adm_start_all,    pattern="^adm_start_all$"))
    app.add_handler(CallbackQueryHandler(cb_adm_cancel_start_all, pattern="^adm_cancel_start_all$"))
    app.add_handler(CallbackQueryHandler(cb_adm_stop_all,     pattern="^adm_stop_all$"))
    app.add_handler(CallbackQueryHandler(cb_adm_stopped_bots, pattern="^adm_stopped_bots$"))
    app.add_handler(CallbackQueryHandler(cb_adm_error_bots,   pattern="^adm_error_bots$"))
    app.add_handler(CallbackQueryHandler(cb_adm_running,      pattern="^adm_running$"))
    app.add_handler(CallbackQueryHandler(cb_adm_rbot,         pattern=r"^adm_rbot_.+"))
    app.add_handler(CallbackQueryHandler(cb_admbact,          pattern=r"^admbact_(stop|restart|start|logs|save|transfer)_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_pending,      pattern="^adm_pending$"))
    app.add_handler(CallbackQueryHandler(cb_adm_users_menu,   pattern="^adm_users_menu$"))
    app.add_handler(CallbackQueryHandler(cb_adm_users,        pattern="^adm_users$"))
    app.add_handler(CallbackQueryHandler(cb_adm_users,        pattern=r"^adm_users_page_\d+$"))
    app.add_handler(CallbackQueryHandler(cb_adm_premium_users, pattern="^adm_premium_users$"))
    app.add_handler(CallbackQueryHandler(cb_adm_premium_users, pattern=r"^adm_premium_users_page_\d+$"))
    app.add_handler(CallbackQueryHandler(cb_adm_banned_users,  pattern="^adm_banned_users$"))
    app.add_handler(CallbackQueryHandler(cb_adm_banned_users,  pattern=r"^adm_banned_users_page_\d+$"))
    app.add_handler(CallbackQueryHandler(cb_adm_find_user_id, pattern="^adm_find_user_id$"))
    app.add_handler(CallbackQueryHandler(cb_adm_user_det,     pattern=r"^adm_user_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_set_approval, pattern=r"^adm_set_approval_.+_(on|off)$"))
    app.add_handler(CallbackQueryHandler(cb_adm_approval_toggle, pattern="^adm_approval_toggle$"))
    app.add_handler(CallbackQueryHandler(cb_adm_approval_set, pattern=r"^adm_approval_set_(on|off)$"))
    app.add_handler(CallbackQueryHandler(cb_adm_ban,          pattern="^adm_ban$"))
    app.add_handler(CallbackQueryHandler(cb_adm_unban,        pattern="^adm_unban$"))
    app.add_handler(CallbackQueryHandler(cb_adm_ban_id,       pattern=r"^adm_ban_id_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_unban_id,     pattern=r"^adm_unban_id_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_broadcast,    pattern="^adm_broadcast$"))
    app.add_handler(CallbackQueryHandler(cb_adm_bc_cancel,    pattern="^adm_bc_cancel$"))
    app.add_handler(CallbackQueryHandler(cb_adm_bc_send,      pattern="^adm_bc_send$"))
    app.add_handler(CallbackQueryHandler(cb_adm_bot_broadcast,pattern="^adm_bot_broadcast$"))
    app.add_handler(CallbackQueryHandler(cb_adm_bb_pick,      pattern=r"^adm_bb_pick_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_del_broadcast,pattern="^adm_del_broadcast$"))
    app.add_handler(CallbackQueryHandler(cb_adm_delbc,        pattern=r"^adm_delbc_[^c].+"))
    app.add_handler(CallbackQueryHandler(cb_adm_delbc_confirm,pattern=r"^adm_delbc_confirm_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_del_custom_msg,pattern="^adm_del_custom_msg$"))
    app.add_handler(CallbackQueryHandler(cb_adm_del_msg_fwd_mode,pattern="^adm_del_msg_fwd_mode$"))
    app.add_handler(CallbackQueryHandler(cb_adm_delcm,        pattern=r"^adm_delcm_[^c].+"))
    app.add_handler(CallbackQueryHandler(cb_adm_delcm_confirm,pattern=r"^adm_delcm_confirm_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_force_del,    pattern=r"^adm_force_del_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_create_code,  pattern="^adm_create_code$"))
    app.add_handler(CallbackQueryHandler(cb_adm_cplan,        pattern=r"^adm_cplan_\w+"))
    app.add_handler(CallbackQueryHandler(cb_code_do_auto,     pattern="^adm_code_do_auto$"))
    app.add_handler(CallbackQueryHandler(cb_adm_code_do_custom,pattern="^adm_code_do_custom$"))
    app.add_handler(CallbackQueryHandler(cb_adm_give_sub,     pattern="^adm_give_sub$"))
    app.add_handler(CallbackQueryHandler(cb_adm_custom_ram,   pattern="^adm_custom_ram$"))
    app.add_handler(CallbackQueryHandler(cb_adm_customram_users,  pattern="^adm_customram_users$"))
    app.add_handler(CallbackQueryHandler(cb_adm_customram_users,  pattern=r"^adm_customram_users_page_\d+$"))
    app.add_handler(CallbackQueryHandler(cb_adm_customram_set,    pattern=r"^adm_customram_set_\-?\d+$"))
    app.add_handler(CallbackQueryHandler(cb_adm_customram_revoke, pattern=r"^adm_customram_revoke_\-?\d+$"))
    app.add_handler(CallbackQueryHandler(cb_adm_givesub_user, pattern=r"^adm_givesub_[0-9]+$"))
    app.add_handler(CallbackQueryHandler(cb_adm_gsplan,       pattern=r"^adm_gsplan_\w+_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_files_pick,   pattern="^adm_files_pick$"))
    app.add_handler(CallbackQueryHandler(cb_adm_files_pick,   pattern=r"^adm_files_page_\d+$"))
    app.add_handler(CallbackQueryHandler(cb_adm_ufiles,       pattern=r"^adm_ufiles_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_fdet,         pattern=r"^adm_fdet_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_fact,         pattern=r"^adm_fact_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_save_file_pick,pattern="^adm_save_file_pick$"))
    app.add_handler(CallbackQueryHandler(cb_adm_approve,      pattern=r"^adm_approve_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_reject,       pattern=r"^adm_reject_[0-9]+.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_reject_no_reason,pattern=r"^adm_reject_no_reason_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_add_users,       pattern="^adm_add_users$"))
    app.add_handler(CallbackQueryHandler(cb_adm_auto_fetch,      pattern="^adm_auto_fetch$"))
    app.add_handler(CallbackQueryHandler(cb_adm_failed_bc_list,  pattern="^adm_failed_bc_list$"))
    app.add_handler(CallbackQueryHandler(cb_adm_failed_bc_txt,   pattern=r"^adm_failed_bc_txt_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_failed_bc_detail,pattern=r"^adm_failed_bc_(?!list|txt).+"))
    app.add_handler(CallbackQueryHandler(cb_adm_delete_users,    pattern="^adm_delete_users$"))
    app.add_handler(CallbackQueryHandler(cb_adm_fetch_hb_users,  pattern="^adm_fetch_hb_users$"))
    app.add_handler(CallbackQueryHandler(cb_adm_force_join,   pattern="^adm_force_join$"))
    app.add_handler(CallbackQueryHandler(cb_adm_fj_toggle,    pattern=r"^adm_fj_(on|off)$"))
    app.add_handler(CallbackQueryHandler(cb_adm_fj_add_channel,  pattern="^adm_fj_add_channel$"))
    app.add_handler(CallbackQueryHandler(cb_adm_fj_remove_channel,pattern="^adm_fj_remove_channel$"))
    app.add_handler(CallbackQueryHandler(cb_adm_fj_del,       pattern=r"^adm_fj_del_\d+$"))
    app.add_handler(CallbackQueryHandler(cb_adm_set_qr,       pattern="^adm_set_qr$"))
    app.add_handler(CallbackQueryHandler(cb_adm_restore_qr,   pattern="^adm_restore_qr$"))
    app.add_handler(CallbackQueryHandler(cb_adm_set_upi,      pattern="^adm_set_upi$"))
    app.add_handler(CallbackQueryHandler(cb_adm_set_custom_uptime, pattern="^adm_set_custom_uptime$"))
    app.add_handler(CallbackQueryHandler(cb_adm_payments,     pattern="^adm_payments$"))
    app.add_handler(CallbackQueryHandler(cb_adm_pay_view,     pattern=r"^adm_pay_view_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_pay_verify,   pattern=r"^adm_pay_verify_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_pay_deny,     pattern=r"^adm_pay_deny_[0-9]+$"))
    app.add_handler(CallbackQueryHandler(cb_adm_replace_file, pattern="^adm_replace_file$"))
    app.add_handler(CallbackQueryHandler(cb_adm_replace_pick, pattern=r"^adm_replace_pick_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_github_import,pattern="^adm_github_import$"))
    app.add_handler(CallbackQueryHandler(cb_adm_del_error_files, pattern="^adm_del_error_files$"))
    app.add_handler(CallbackQueryHandler(cb_adm_del_stopped_bots, pattern="^adm_del_stopped_bots$"))
    app.add_handler(CallbackQueryHandler(cb_adm_security_bots,  pattern="^adm_security_bots$"))
    app.add_handler(CallbackQueryHandler(cb_adm_secbot,         pattern=r"^adm_secbot_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_force_start,    pattern=r"^adm_force_start_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_new_plan,        pattern="^adm_new_plan$"))
    app.add_handler(CallbackQueryHandler(cb_adm_manage_plans,    pattern="^adm_manage_plans$"))
    app.add_handler(CallbackQueryHandler(cb_adm_mplan,           pattern=r"^adm_mplan_.+"))
    app.add_handler(CallbackQueryHandler(cb_adm_gen_backup,      pattern="^adm_gen_backup$"))
    app.add_handler(CallbackQueryHandler(cb_adm_gen_backup_yes,  pattern="^adm_gen_backup_yes$"))
    app.add_handler(CallbackQueryHandler(cb_adm_gen_backup_no,   pattern="^adm_gen_backup_no$"))
    app.add_handler(CallbackQueryHandler(cb_adm_upload_backup,   pattern="^adm_upload_backup$"))

    async def post_init(application):
        global _cloud_bot_ref, _cloud_lock
        _cloud_lock = asyncio.Lock()
        _cloud_bot_ref = application.bot

        restored = await load_state(application.bot)
        if not restored:
            d = _load()
            _restore_stats.update({
                "files":   sum(len(u.get("bots", [])) for u in d.get("users", {}).values()),
                "users":   len(d.get("users", {})),
                "premium": sum(1 for u in d.get("users", {}).values() if u.get("plan", "free") != "free"),
                "banned":  len(d.get("bans", [])),
            })

        print_startup_dashboard(
            _restore_stats["files"], _restore_stats["users"],
            _restore_stats["premium"], _restore_stats["banned"],
            restored,
        )

        asyncio.create_task(_send_expiry_warnings(application))
        asyncio.create_task(_cloud_hourly_backup(application))
        asyncio.create_task(_bio_enforcer_loop(application))
        asyncio.create_task(_ram_enforcer_loop(application))
        asyncio.create_task(_zombie_reaper_loop(application))
        asyncio.create_task(_auto_delete_stopped_bots_loop(application))

    app.post_init = post_init

    log.info("Bot polling. Ready!")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    import time as _time
    keep_alive()  # Step 1: start Flask keep-alive server

    _RESTART_DELAY = 5
    _attempt = 0
    while True:
        _attempt += 1
        print(f"[WATCHDOG] Starting bot (attempt {_attempt})…")
        try:
            # run_polling() closes its event loop on exit; give every restart
            # a fresh one so the watchdog can actually recover from crashes.
            asyncio.set_event_loop(asyncio.new_event_loop())
            main()
        except SystemExit:
            pass
        except KeyboardInterrupt:
            print("[WATCHDOG] Stopped by user.")
            break
        except Exception as _e:
            print(f"[WATCHDOG] Bot crashed: {_e}")
        print(f"[WATCHDOG] Bot stopped. Restarting in {_RESTART_DELAY}s…")
        _time.sleep(_RESTART_DELAY)

