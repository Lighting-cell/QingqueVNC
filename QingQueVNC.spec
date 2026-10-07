# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all
from pathlib import Path
import sysconfig

ROOT = Path(SPECPATH).resolve()
PYSIDE_ROOT = Path(sysconfig.get_paths()['purelib']) / 'PySide6'
datas = [
    (str(ROOT / 'vendor' / 'TigerVNC' / 'vncviewer.exe'), 'TigerVNC'),
    (str(ROOT / 'assets' / 'qingquevnc.png'), 'assets'),
    (
        str(PYSIDE_ROOT / 'translations' / 'qtbase_zh_CN.qm'),
        'PySide6/translations',
    ),
]
binaries = [
    (
        str(PYSIDE_ROOT / 'plugins' / 'platforms' / 'qwindows.dll'),
        'PySide6/plugins/platforms',
    )
]
hiddenimports = []

for package in ('qdarktheme', 'darkdetect', 'paramiko', 'bcrypt', 'nacl', 'cryptography'):
    package_datas, package_binaries, package_hiddenimports = collect_all(package)
    datas += package_datas
    binaries += package_binaries
    hiddenimports += package_hiddenimports

a = Analysis(
    [str(ROOT / 'vnc_tunnel_manager.pyw')],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='QingQueVNC',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    icon=str(ROOT / 'assets' / 'qingquevnc.ico'),
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
