$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    python -m venv (Join-Path $root '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the isolated build environment.' }
}
& $python -m pip install --disable-pip-version-check -r (Join-Path $root 'requirements-build.txt')
if ($LASTEXITCODE -ne 0) { throw 'Could not install the pinned build dependencies.' }
& $python -c 'import tkinter as tk; root=tk.Tk(); root.withdraw(); root.destroy()'
if ($LASTEXITCODE -ne 0) { throw 'Python Tcl/Tk resources are missing. Install a Windows Python distribution with working tkinter before packaging.' }
& $python (Join-Path $root 'scripts\generate_icon.py')
if ($LASTEXITCODE -ne 0) { throw 'Could not generate the HexiKeys icon.' }
& $python -m PyInstaller --clean --noconfirm --onefile --windowed --name HexiKeys --distpath (Join-Path $root 'dist') --workpath (Join-Path $root 'build') --specpath $root --add-data ((Join-Path $root 'assets') + ';assets') --icon (Join-Path $root 'assets\hexikeys.ico') (Join-Path $root 'app.py')
if ($LASTEXITCODE -ne 0) { throw 'HexiKeys packaging failed.' }
Write-Output (Join-Path $root 'dist\HexiKeys.exe')
