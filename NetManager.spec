# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['interface.py'],
    pathex=['.venv/Lib/site-packages'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'scapy.all', 'scapy.layers.l2', 'scapy.layers.inet',
        'scapy.layers.dns', 'scapy.layers.tls.all',
    ],
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
    name='NetManager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
)