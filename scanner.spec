# elect-rix Shadow AI Scanner — PyInstaller Build Spec
#
# Builds standalone executables for each platform. No Python needed
# on the client machine — the executable includes the Python runtime
# and all dependencies bundled inside.
#
# Build on each platform:
#   Linux:   pyinstaller scanner.spec --onefile --name scanner
#   macOS:   pyinstaller scanner.spec --onefile --name scanner
#   Windows: pyinstaller scanner.spec --onefile --name scanner.exe
#
# Output goes to dist/scanner (or dist/scanner.exe on Windows)
# Copy to: usb-audit-kit/bin/<platform>/scanner

block_cipher = None

a = Analysis(
    ['scanner.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('ai_domains.json', '.'),
        ('practice_software.json', '.'),
        ('report_template.html', '.'),
    ],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas', 'PIL'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='scanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)