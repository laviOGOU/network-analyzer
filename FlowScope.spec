# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['psycopg', 'psycopg_binary', 'fpdf', 'dotenv', 'psutil', 'pydantic']
hiddenimports += collect_submodules('uvicorn')
hiddenimports += collect_submodules('webview')
hiddenimports += collect_submodules('backend')
hiddenimports += collect_submodules('agent')


a = Analysis(
    ['flowscope-desktop.py'],
    pathex=[],
    binaries=[],
    datas=[('web', 'web'), ('.env.example', '.'), ('agent', 'agent')],
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
    name='FlowScope',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['web/static/flowscope.ico'],
)
