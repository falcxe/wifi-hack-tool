"""Fetch the external tools the pipeline needs, with pinned SHA-256 digests.

Nothing here is trusted implicitly: every download is verified against a digest
recorded from the project's official GitHub release API response, and a mismatch
deletes the file rather than executing it.

Verified sources (GitHub release API, read during development):

* hashcat  v7.1.2 -- single ``.7z`` archive, sha256 recorded below.
* WPAWolf v1.3.0  -- standalone Windows ``.exe``, sha256 recorded below.

hashcat ships only a 7-Zip archive, and that archive is BCJ2-compressed --
``py7zr`` refuses it. So extraction goes through the ``7zr.exe`` the project
ships in ``assets/``, and ``py7zr`` is only the fallback for archives that do
happen to be plain. Without any extractor the archive is kept in ``assets/`` and
the user is told the exact command to run; the tool stays usable.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = PROJECT_ROOT / "assets"

USER_AGENT = "wifi_tool/0.1 (+https://localhost)"
CHUNK = 1 << 16


class InstallError(RuntimeError):
    """Raised when a tool could not be downloaded or installed."""


@dataclass
class Tool:
    key: str
    title: str
    url: str = ""
    sha256: str = ""
    filename: str = ""
    # Where the tool ends up once installed, relative to assets/. For an archive
    # this is the *folder* that stays intact, because the executable is useless
    # without the module tree beside it.
    installed_name: str = ""
    kind: str = "exe"  # "exe" | "archive"
    note: str = ""
    # False when the project publishes no ready-to-run binary we can fetch and
    # verify; such tools are listed in the UI with manual instructions instead.
    auto: bool = True
    manual: str = ""
    alternatives: List[str] = field(default_factory=list)

    @property
    def target(self) -> Path:
        return ASSETS_DIR / (self.installed_name or self.filename)


TOOLS: dict[str, Tool] = {
    "wpawolf": Tool(
        key="wpawolf",
        title="wpawolf (конвертер хэшей, Windows)",
        url=(
            "https://github.com/StrongWind1/WPAWolf/releases/download/"
            "v1.3.0/wpawolf-windows-x86_64-msvc.exe"
        ),
        sha256="f68f47d63c8c80e5ad143bfc45cbdc80b4d3d9bbcc4e24d74144696e226c72d9",
        filename="wpawolf-windows-x86_64-msvc.exe",
        installed_name="wpawolf.exe",
        kind="exe",
        note="заменяет hcxpcapngtool, который на Windows не поддерживается",
    ),
    "hashcat": Tool(
        key="hashcat",
        title="hashcat (подбор пароля)",
        url=(
            "https://github.com/hashcat/hashcat/releases/download/"
            "v7.1.2/hashcat-7.1.2.7z"
        ),
        # Verified twice on 2026-10-14: read from the GitHub release API's own
        # `digest` field, then confirmed against the downloaded bytes.
        sha256="80db0316387794ce9d14ed376da75b8a7742972485b45db790f5f8260307ff98",
        filename="hashcat-7.1.2.7z",
        # The whole extracted folder, not the exe: hashcat cannot start without
        # the OpenCL/modules/kernels tree beside it.
        installed_name="hashcat",
        kind="archive",
        note="BCJ2: распаковывает assets\\7zr.exe, py7zr этот архив не берёт",
        manual=(
            "hashcat -> hashcat.net/forum, скачай Windows-пакет и распакуй 7-Zip.\n"
            "  Папку целиком (hashcat.exe вместе с OpenCL/, modules/, kernels/,\n"
            "  rules/) положи в assets/ -- assets\\hashcat-<версия> подходит,\n"
            "  программа найдёт её сама."
        ),
    ),
}

# Windows archives from hashcat.org mirror the GitHub release; the .zip is
# preferred when present because Python can unpack it without extra tools.
HASHCAT_MIRROR = "https://hashcat.org/files"


def is_installed(tool: Tool) -> bool:
    """True when the tool is usable, not merely present.

    For hashcat that means a complete folder -- the executable *and* its
    ``OpenCL/`` module tree. A lone ``hashcat.exe`` is the state that fails at
    launch with ``./OpenCL/: No such file or directory``, so reporting that as
    installed is what sends someone round in circles. Any versioned folder in
    assets/ counts, because that is how the official archive unpacks.
    """
    if tool.kind != "archive":
        return tool.target.exists()
    if tool.target.is_dir() and (tool.target / "hashcat.exe").exists():
        return (tool.target / "OpenCL").is_dir()
    return any(
        (folder / "hashcat.exe").exists() and (folder / "OpenCL").is_dir()
        for folder in ASSETS_DIR.glob("hashcat*")
        if folder.is_dir()
    )


def missing_tools(auto_only: bool = False) -> List[Tool]:
    return [
        t
        for t in TOOLS.values()
        if not is_installed(t) and (not auto_only or t.auto)
    ]


def manual_tools() -> List[Tool]:
    """Tools that must be installed by hand, with their instructions."""
    return [t for t in TOOLS.values() if not t.auto and not is_installed(t)]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def _download(
    url: str,
    dest: Path,
    sha256: str,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> Path:
    """Stream ``url`` to ``dest``; delete the file unless the digest matches.

    An empty ``sha256`` means the caller has no digest recorded and the download
    is not verified -- but it is *not* compared against "" and reported as a
    mismatch, which is what an unguarded comparison does. Callers that do have a
    digest (every tool here) always pass one; the RockYou archive is the one
    case where the digest covers the *filtered* file rather than the archive,
    so it is verified after filtering instead.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            total = int(response.headers.get("Content-Length") or 0)
            done = 0
            with dest.open("wb") as out:
                while True:
                    block = response.read(CHUNK)
                    if not block:
                        break
                    out.write(block)
                    done += len(block)
                    if on_progress:
                        on_progress(done, total)
    except Exception as exc:  # noqa: BLE001 - surfaced as InstallError
        dest.unlink(missing_ok=True)
        raise InstallError(f"не удалось скачать {url}: {exc}") from exc

    actual = _sha256(dest)
    if sha256 and actual != sha256:
        dest.unlink(missing_ok=True)
        raise InstallError(
            "контрольная сумма не совпала, файл удалён\n"
            f"  ожидалось: {sha256}\n  получено : {actual}"
        )
    return dest


#: Shown when an install fails: the exact command to retry with, rather than a
#: ``pip install`` the uv-based setup does not use.
_INSTALL_HINT = "uv run python tools/setup.py"

#: The standalone 7zr console binary. Fetched rather than committed: a 600 KB
#: third-party executable in the repository is a licence and a size argument
#: forever. Public domain, straight from 7-zip.org.
SEVENZIP_URL = "https://www.7-zip.org/a/7zr.exe"
SEVENZIP_SHA256 = "256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282"


def ensure_7z(
    *, on_log: Optional[Callable[[str], None]] = None
) -> Optional[Path]:
    """Return a working extractor for hashcat's archive, downloading one if needed.

    Without this the automatic install could not finish on a fresh clone: hashcat
    ships BCJ2-compressed, py7zr refuses it outright, and the 7z that used to sit
    in assets/ is not in the repository. A clean checkout therefore had no
    extractor at all, and the install died with "нечем распаковать .7z" while
    telling the user to check that file, which was never there.
    """
    log = on_log or (lambda _line: None)
    found = find_7z()
    if found is not None:
        return found

    local = ASSETS_DIR / "7zr.exe"
    log("Extractor for .7z: downloading 7zr.exe from 7-zip.org...")
    try:
        ASSETS_DIR.mkdir(parents=True, exist_ok=True)
        _download(SEVENZIP_URL, local, SEVENZIP_SHA256)
    except InstallError as exc:
        log(f"  failed: {exc}")
        log("  install 7-Zip manually: https://www.7-zip.org")
        return None
    log("  7zr.exe: checksum OK")
    return local if local.exists() else None


# --------------------------------------------------------------------------
# Npcap
# --------------------------------------------------------------------------
#
# Different in kind from everything above, and worth spelling out.
#
# Npcap is not a program you drop in a folder: it is a signed installer that
# registers an NDIS filter driver and a lightweight filter driver. Three of its
# own documented facts shape what can be automated here.
#
# * ``/S`` (silent install) is "available only with Npcap OEM". The free
#   installer from npcap.com shows its GUI. Pretending otherwise by passing
#   ``/S`` produces a window that appears to be doing nothing.
# * ``/dot11_support=yes`` *does* work in GUI mode and preselects the "Support
#   raw 802.11 traffic (and monitor mode)" box -- which is the one option this
#   project cannot do without.
# * Installing a filter driver "may cause brief interruptions to network
#   connectivity" (Npcap issue #53), and may return 3010, reboot required.
#
# So this step downloads and verifies the official installer, refuses to run
# without elevation, launches it with the needed option already ticked, and
# reads the documented exit code back. The click-through is the user's, not a
# limitation worked around.

NPCAP_URL = "https://npcap.com/dist/npcap-{version}.exe"
NPCAP_VERSION = "1.83"
#: Verified against the signed installer from npcap.com on 2026-10-14; the file
#: carries a valid Authenticode signature from Nmap Software LLC.
NPCAP_SHA256 = "1bf58936296992d6b03e6c36621ca8239a786c13b89d761d210fa21731567ac0"

#: Exit codes, from the Npcap users' guide. Anything else is reported as-is.
NPCAP_EXIT = {
    0: "установлено",
    1: "установка отменена (кнопка Cancel)",
    2: "установка прервана скриптом",
    350: "не удалось, нужен перезапуск",
    1618: "установка уже идёт, дождись её окончания",
    1633: "Npcap не поддерживается на этой платформе",
    3010: "установлено, требуется перезагрузка",
}


def npcap_state() -> dict:
    """What Npcap looks like on this machine. Never raises, never changes.

    Each field is read independently and an unknown one stays ``None``. They
    used to be read in one ``try`` where a missing ``DisplayVersion`` value --
    which older builds do not write -- aborted the whole function and reported
    an installed Npcap as having no version, no raw-802.11 support and no
    helper, i.e. as not installed at all.
    """
    import os

    state: dict = {"installed": False, "dot11": None, "version": None,
                   "wlan_helper": None, "path": None}
    try:
        import winreg
    except ImportError:
        return state

    def read(path: str, *names: str):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                for name in names:
                    try:
                        value, _ = winreg.QueryValueEx(key, name)
                        return value
                    except OSError:
                        continue
        except OSError:
            return None
        return None

    service = r"SYSTEM\CurrentControlSet\Services\npcap"
    if read(service, "ImagePath") is not None:
        state["installed"] = True
        state["version"] = read(service, "DisplayVersion", "Version")
    raw = read(service + r"\Parameters", "Dot11Support")
    if raw is not None:
        try:
            state["dot11"] = bool(int(raw))
        except (TypeError, ValueError):
            state["dot11"] = None

    helper = (Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32"
              / "Npcap" / "WlanHelper.exe")
    state["wlan_helper"] = helper if helper.exists() else None
    state["path"] = helper.parent if helper.parent.exists() else None
    return state


def npcap_needs_install() -> bool:
    """True when capture is impossible or unconfigured.

    Missing Npcap and missing raw-802.11 support are different failures and get
    different messages: the first needs the installer, the second needs the one
    checkbox, and sending someone to re-run the whole install over a single
    unticked box is the advice that costs an afternoon.
    """
    state = npcap_state()
    return not state["installed"] or not state["dot11"]


def install_npcap(
    *,
    on_log: Optional[Callable[[str], None]] = None,
    assume_yes: bool = False,
) -> dict:
    """Download, verify and launch the official Npcap installer.

    Never raises. Returns a dict with ``status`` (one of ``installed``,
    ``already`` / ``already-no-dot11``, ``denied``, ``cancelled``, ``reboot``,
    ``failed``), ``message`` and ``code``.

    The GUI appears: ``/S`` is an OEM-only flag and the free installer has no
    quiet mode. ``/dot11_support=yes`` is passed anyway, because it works in
    GUI mode and ticks the box this project needs before the window opens.
    """
    log = on_log or (lambda _line: None)
    state = npcap_state()
    if state["installed"] and state["dot11"]:
        log(f"Npcap {state['version'] or ''} уже установлен, raw 802.11 включён.")
        return {"status": "already", "message": "установлен", "code": 0}
    if state["installed"] and not state["dot11"]:
        log("Npcap установлен, но без поддержки raw 802.11 — переустановлю "
            "с нужной галочкой.")

    from .assets import is_admin

    if not is_admin():
        message = (
            "Npcap ставит драйвер, поэтому нужны права администратора.\n"
            "  Запусти в терминале от администратора, либо просто запусти\n"
            f"  {_INSTALL_HINT} --npcap повторно оттуда."
        )
        log(message)
        return {"status": "denied", "message": message, "code": None}

    url = NPCAP_URL.format(version=NPCAP_VERSION)
    log(f"Npcap: скачиваю {url}")
    installer_path = Path(tempfile.gettempdir()) / f"npcap-{NPCAP_VERSION}.exe"
    try:
        _download(url, installer_path, NPCAP_SHA256)
    except InstallError as exc:
        log(f"  не получилось: {exc}")
        return {"status": "failed", "message": str(exc), "code": None}
    log("  подпись Nmap Software LLC, SHA-256 OK")

    args = ["/dot11_support=yes"]
    if assume_yes:
        # Still no /S: it is OEM-only and would be ignored by the free build.
        args.append("/winpcap_mode=yes")
    args.append(f"/D={installer_path.parent}")

    log("")
    log("  Сейчас откроется установщик Npcap. Нажми Install и дождись конца.")
    log("  Галочка «Support raw 802.11 traffic (and monitor mode)» уже стоит.")
    log("  Установка драйвера может на пару секунд оборвать сеть — это")
    log("  задокументированное поведение Npcap, не поломка.")
    log("")

    try:
        proc = subprocess.run([str(installer_path), *args], timeout=900)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        message = "установщик не ответил за 15 минут"
        log(message)
        return {"status": "failed", "message": message, "code": None}
    finally:
        installer_path.unlink(missing_ok=True)

    meaning = NPCAP_EXIT.get(code, f"код {code}")
    log(f"  установщик завершился: {meaning}")
    if code == 0:
        return {"status": "installed", "message": meaning, "code": code}
    if code == 3010:
        return {"status": "reboot", "message": meaning, "code": code}
    if code in (1, 2):
        return {"status": "cancelled", "message": meaning, "code": code}
    return {"status": "failed", "message": meaning, "code": code}


def find_7z() -> Optional[Path]:
    """Locate a 7-Zip / 7za / 7zr binary for unpacking hashcat's archive.

    assets/ is checked first, then PATH, then the two places 7-Zip installs
    itself into. Deliberately a pure lookup -- a caller that only wants to know
    what is available should not be surprised by a download; see
    :func:`ensure_7z` for that.
    """
    for name in ("7z.exe", "7za.exe", "7zr.exe"):
        local = ASSETS_DIR / name
        if local.exists():
            return local
    for name in ("7z", "7za", "7zr"):
        found = shutil.which(name)
        if found:
            return Path(found)
    guesses = [
        Path(r"C:\Program Files\7-Zip\7z.exe"),
        Path(r"C:\Program Files (x86)\7-Zip\7z.exe"),
    ]
    for guess in guesses:
        if guess.exists():
            return guess
    return None


def _extract_7z(archive: Path, dest: Path) -> Optional[Path]:
    """Extract ``archive`` into ``dest``; return the installed exe or None.

    ``py7zr`` first (it is already a dependency, so this path needs no external
    binary), then the 7z in ``assets/`` or on PATH.

    A py7zr *failure* falls through to 7z instead of raising: hashcat's archive
    is BCJ2-compressed, which py7zr refuses outright
    (``UnsupportedCompressionMethodError``), and that is the expected outcome on
    a perfectly good machine. Raising there skipped the 7z fallback that actually
    works and turned every automatic install into "нечем распаковать .7z" while
    a working ``assets/7zr.exe`` sat in the very folder being written to.
    """
    dest.mkdir(parents=True, exist_ok=True)
    try:
        import py7zr  # type: ignore

        with py7zr.SevenZipFile(archive, mode="r") as zf:
            zf.extractall(path=dest)
        found = _locate_hashcat(dest)
        if found:
            return found
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001 - 7z below is the real answer
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True, exist_ok=True)
        print(f"  py7zr не справился ({type(exc).__name__}), пробую 7z...")

    exe = ensure_7z()
    if exe is None:
        return None
    proc = subprocess.run(
        [str(exe), "x", "-y", f"-o{dest}", str(archive)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    if proc.returncode != 0:
        raise InstallError(
            f"7z вернул код {proc.returncode}: {(proc.stderr or '').strip()[:200]}"
        )
    return _locate_hashcat(dest)


def _locate_hashcat(root: Path) -> Optional[Path]:
    """Find hashcat.exe under ``root``."""
    found = root / "hashcat.exe"
    if found.exists():
        return found
    for candidate in sorted(root.rglob("hashcat.exe")):
        return candidate
    return None


def _archive_root(exe: Path) -> Path:
    """The directory that has to stay intact for hashcat to run.

    hashcat resolves its module tree (``OpenCL/``, ``modules/``, ``kernels/``,
    ``rules/``) relative to its own executable, so the whole extracted folder is
    the unit of installation -- not the single exe inside it.
    """
    return exe.parent


def install(
    tool: Tool,
    *,
    on_log: Optional[Callable[[str], None]] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> Path:
    """Download and install one tool. Blocking; call via ``asyncio.to_thread``."""
    log = on_log or (lambda _line: None)
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)

    if not tool.auto:
        raise InstallError(f"{tool.title}: автоустановка недоступна\n{tool.manual}")
    if is_installed(tool):
        log(f"{tool.title}: уже установлен")
        return tool.target

    log(f"{tool.title}: скачиваю...")
    log(f"  {tool.url}")
    tool_installed = tool.target

    tmp_dir = Path(tempfile.mkdtemp(prefix="wifi_tool_dl_"))
    try:
        archive = tmp_dir / tool.filename
        _download(tool.url, archive, tool.sha256, on_progress)
        log(f"{tool.title}: контрольная сумма OK ({tool.sha256[:16]}…)")

        if tool.kind == "exe":
            shutil.copy2(archive, tool.target)
        else:
            # Extract into a staging folder, never into assets/. hashcat loads
            # ./OpenCL, ./modules, ./kernels and ./rules relative to its own
            # executable, so moving hashcat.exe up into assets/ on its own leaves
            # it unable to start at all ("./OpenCL/: No such file or directory").
            # It stays as a complete directory, and :func:`find_hashcat` already
            # looks inside ``hashcat-<version>/``, which is how the official
            # archive unpacks.
            staging = ASSETS_DIR / f".{tool.key}_staging"
            shutil.rmtree(staging, ignore_errors=True)
            exe = _extract_7z(archive, staging)
            if exe is None:
                shutil.rmtree(staging, ignore_errors=True)
                # Keep the archive so the user can unpack it themselves.
                kept = ASSETS_DIR / tool.filename
                shutil.copy2(archive, kept)
                raise InstallError(
                    f"{tool.title}: нечем распаковать .7z\n"
                    f"  архив сохранён: {kept}\n"
                    "  распаковщик не нашёлся и скачать его не удалось —\n"
                    "  поставь 7-Zip вручную: https://www.7-zip.org\n"
                    f"  и запусти настройку ещё раз: {_INSTALL_HINT}"
                )
            unpacked_root = _archive_root(exe)
            final_root = ASSETS_DIR / unpacked_root.name
            if final_root.resolve() == staging.resolve():
                final_root = ASSETS_DIR / "hashcat"
            if final_root.exists():
                shutil.rmtree(final_root, ignore_errors=True)
            shutil.move(str(unpacked_root), str(final_root))
            shutil.rmtree(staging, ignore_errors=True)
            installed = final_root / "hashcat.exe"
            if not installed.exists():
                raise InstallError(f"{tool.title}: после распаковки нет hashcat.exe")
            tool_installed = installed
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    log(f"{tool.title}: установлен -> {tool_installed}")
    return tool_installed


async def install_all(
    keys: Optional[List[str]] = None,
    *,
    on_log: Optional[Callable[[str], None]] = None,
    on_progress: Optional[Callable[[str, int, int], None]] = None,
) -> dict[str, str]:
    """Install the requested tools (default: everything missing).

    Returns ``{key: "ok" | error message}``; never raises for a single failure.
    """
    log = on_log or (lambda _line: None)
    wanted = keys or [t.key for t in missing_tools(auto_only=True)]
    results: dict[str, str] = {}

    for key in wanted:
        tool = TOOLS.get(key)
        if tool is None:
            results[key] = "неизвестный инструмент"
            continue

        def progress(done: int, total: int, _key: str = key) -> None:
            if on_progress:
                on_progress(_key, done, total)

        try:
            await asyncio.to_thread(install, tool, on_log=log, on_progress=progress)
            results[key] = "ok"
        except InstallError as exc:
            results[key] = str(exc)
            log(f"ОШИБКА: {exc}")
        except Exception as exc:  # noqa: BLE001
            results[key] = f"непредвиденная ошибка: {exc}"
            log(f"ОШИБКА: {exc}")
    return results


def summary() -> str:
    """One-line status suitable for the UI."""
    done = [t for t in TOOLS.values() if is_installed(t)]
    if not done:
        return "ничего не установлено"
    return "установлено: " + ", ".join(t.title.split(" (")[0] for t in done)


# --------------------------------------------------------------------------
# Dictionaries
# --------------------------------------------------------------------------
#
# Not part of TOOLS: these are not single downloaded binaries but a filter run
# over a 53 MB archive, so they need their own step. They are also the two
# stages that matter most -- without RockYou the ladder is down to targeted
# candidates and brute force.

#: Recorded in assets/wordlists-info.json, which ships with the repository, so
#: the expected digest is verifiable without reading this file.
_INFO_NAME = "wordlists-info.json"

#: File names written into assets/. Kept in step with options.WORDLIST_NAMES /
#: QUICK_WORDLIST_NAMES, which is what the ladder and the form actually read.
ROCKYOU_WORDLIST_NAME = "rockyou-wpa.txt"
QUICK_WORDLIST_NAME = "probable-wpa.txt"

#: rockyou.txt is 14.3M lines; a WPA key is 8..63 bytes, which leaves 9.6M.
#: Both numbers are checked against the recorded file rather than assumed.
_MIN_PSK = 8
_MAX_PSK = 63


def _wordlist_info() -> dict:
    path = ASSETS_DIR / _INFO_NAME
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def installed_wordlists() -> dict[str, Path]:
    """The dictionaries present in assets/, by role.

    RockYou is looked up by name and size rather than through the generic
    dictionary finder: ``assets/wordlist.txt`` is a 136-line test fixture that
    the repository ships, and reporting it as RockYou hides the fact that the
    real list is missing.
    """
    from .options import (find_extra_wordlist, find_quick_wordlist, find_rockyou,
                       find_wordlist)

    found: dict[str, Path] = {}
    rockyou = find_rockyou(ASSETS_DIR)
    if rockyou is not None:
        found["RockYou"] = rockyou
    quick = find_quick_wordlist(ASSETS_DIR)
    if quick is not None:
        found["частые пароли"] = quick
    extra = find_extra_wordlist(ASSETS_DIR)
    if extra is not None:
        found["доп. словарь"] = extra
    other = find_wordlist(ASSETS_DIR)
    if other is not None and other != rockyou:
        found["свой словарь"] = other
    return found


def _filter_wpa(source: Path, dest: Path) -> int:
    """Copy the 8..63-byte lines of ``source`` into ``dest``; return the count.

    Byte-wise, never decoded: a candidate's WPA length is measured in bytes, so
    ``пароль`` counts as 12 (16 bytes) and drops out exactly as hashcat's kernel
    would reject it. Decoding to str first and counting characters would keep
    six-byte candidates and drop real eight-byte ones.
    """
    kept = 0
    with source.open("rb") as fin, dest.open("wb") as fout:
        for raw in fin:
            candidate = raw.rstrip(b"\r\n")
            if not (_MIN_PSK <= len(candidate) <= _MAX_PSK):
                continue
            fout.write(candidate + b"\n")
            kept += 1
    return kept


def install_wordlists(
    *,
    on_log: Optional[Callable[[str], None]] = None,
    on_progress: Optional[Callable[[str, int, int], None]] = None,
) -> dict[str, str]:
    """Fetch RockYou WPA and the quick list, verifying digests. Never raises.

    Returns ``{name: "ok" | message}``. A 53 MB download that fails should not
    take the whole setup down, and a machine that already has a dictionary
    should not download another one.
    """
    log = on_log or (lambda _line: None)
    info = _wordlist_info()
    results: dict[str, str] = {}

    from .options import find_quick_wordlist, find_rockyou

    quick = find_quick_wordlist(ASSETS_DIR)
    if quick is not None:
        log(f"Словарь частых паролей: уже есть ({quick.name})")
        results["quick"] = "ok"
    elif info.get("quick_source"):
        name = QUICK_WORDLIST_NAME
        log(f"Словарь частых паролей: скачиваю {name}...")
        tmp = Path(tempfile.gettempdir()) / name
        try:
            _download(info["quick_source"], tmp, info.get("quick_sha256") or "")
            expected = info.get("quick_candidates")
            count = sum(1 for _ in tmp.open("rb"))
            if expected and count != expected:
                tmp.unlink(missing_ok=True)
                raise InstallError(
                    f"строк {count}, ожидалось {expected}"
                )
            ASSETS_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copy2(tmp, ASSETS_DIR / name)
            log(f"  {name}: {count:,} кандидатов, OK")
            results["quick"] = "ok"
        except InstallError as exc:
            log(f"  не получилось: {exc}")
            results["quick"] = str(exc)
        finally:
            tmp.unlink(missing_ok=True)

    rockyou = find_rockyou(ASSETS_DIR)
    if rockyou is not None:
        log(f"RockYou WPA: уже есть ({rockyou.name})")
        results["rockyou"] = "ok"
    elif info.get("source") and info.get("rockyou_wpa_sha256"):
        log("RockYou WPA: скачиваю архив (~53 МБ), это займёт минуту...")
        tmp_dir = Path(tempfile.mkdtemp(prefix="wifi_tool_wl_"))
        try:
            archive = tmp_dir / "rockyou.txt.tar.gz"
            _download(info["source"], archive, info.get("rockyou_archive_sha256") or "",
                      on_progress=(lambda d, t: on_progress("rockyou", d, t))
                      if on_progress else None)
            log(f"  архив SHA-256 OK, распаковываю...")
            proc = subprocess.run(["tar", "-xzf", str(archive), "-C", str(tmp_dir)],
                                  capture_output=True, text=True, errors="replace",
                                  timeout=900)
            if proc.returncode != 0:
                raise InstallError(f"tar вернул код {proc.returncode}")
            log("  фильтрую по длине WPA (8–63 байта)...")
            dest = ASSETS_DIR / ROCKYOU_WORDLIST_NAME
            count = _filter_wpa(tmp_dir / "rockyou.txt", dest)
            actual = _sha256(dest)
            expected = info["rockyou_wpa_sha256"]
            if actual != expected:
                dest.unlink(missing_ok=True)
                raise InstallError(
                    "собранный словарь не совпал с записанным SHA-256,\n"
                    f"  ожидалось: {expected}\n  получено : {actual}"
                )
            want_count = info.get("rockyou_wpa_candidates")
            if want_count and count != want_count:
                dest.unlink(missing_ok=True)
                raise InstallError(f"кандидатов {count}, ожидалось {want_count}")
            log(f"  {ROCKYOU_WORDLIST_NAME}: {count:,} кандидатов, SHA-256 OK")
            results["rockyou"] = "ok"
        except InstallError as exc:
            log(f"  не получилось: {exc}")
            results["rockyou"] = str(exc)
        except Exception as exc:  # noqa: BLE001
            log(f"  неожиданная ошибка: {exc}")
            results["rockyou"] = str(exc)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return results