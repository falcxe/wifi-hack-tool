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
    """Stream ``url`` to ``dest``; delete the file unless the digest matches."""
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
    if actual != sha256:
        dest.unlink(missing_ok=True)
        raise InstallError(
            "контрольная сумма не совпала, файл удалён\n"
            f"  ожидалось: {sha256}\n  получено : {actual}"
        )
    return dest


def find_7z() -> Optional[Path]:
    """Locate a 7-Zip / 7za / 7zr binary for unpacking hashcat's archive.

    assets/ is checked first: the project ships a standalone ``7zr.exe`` there,
    and telling the user to ``pip install py7zr`` while a working extractor sits
    in the same folder is the kind of advice that costs an afternoon.
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

    exe = find_7z()
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
                    "  в папке assets уже лежит 7zr.exe — проверь, что он на месте,\n"
                    "  либо поставь 7-Zip (https://7-zip.org) или выполни:\n"
                    "    python -m pip install py7zr\n"
                    "  и запусти настройку ещё раз."
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