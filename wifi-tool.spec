# PyInstaller spec for a single-file Windows build of WifiHackTool.
#
# Built from ``main.py`` (the bare-clone entry point), not the installed
# console script: PyInstaller needs a real file to start the dependency
# graph from, and the two are identical two-line wrappers around
# ``wifi_tool.cli.main`` (see main.py).
#
# ``opentui`` ships a compiled extension (``opentui_bindings.*.pyd``) and a
# native DLL + Tree-sitter query files as package data, none of which
# PyInstaller's import scan can see on its own -- it only follows ``import``
# statements. ``collect_all`` pulls in all three (binaries, data files, and
# any hidden submodule imports), so leaving it out silently drops the DLL and
# the exe fails at startup only on a machine that doesn't already have it
# cached from a previous run.
#
# ``assets/`` (hashcat, wordlists, rules -- several hundred MB) is
# deliberately NOT bundled: those are fetched on demand by
# ``tools/setup.py`` / the first-run flow, not shipped inside the exe, the
# same way a cloned checkout works today.
from PyInstaller.utils.hooks import collect_all

datas = []
binaries = []
hiddenimports = []
for pkg in ("opentui",):
    pkg_datas, pkg_binaries, pkg_hidden = collect_all(pkg)
    datas += pkg_datas
    binaries += pkg_binaries
    hiddenimports += pkg_hidden

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="wifi-tool",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    # A console app: the TUI renders over stdout/stdin, so a windowed (GUI)
    # build with no console would start with nothing to draw into.
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
