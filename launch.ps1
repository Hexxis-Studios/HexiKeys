$ErrorActionPreference = 'Stop'
$appDirectory = $PSScriptRoot
$runtimeDirectory = Join-Path $env:LOCALAPPDATA 'HexiKeys\python-runtime'
$runtimePython = Join-Path $runtimeDirectory 'Scripts\python.exe'
$runtimePythonWindowed = Join-Path $runtimeDirectory 'Scripts\pythonw.exe'
$requirements = Join-Path $appDirectory 'requirements.txt'

function Show-LaunchError([string]$message) {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($message, 'HexiKeys could not start', 'OK', 'Error') | Out-Null
}

try {
    $packagedApp = Join-Path $appDirectory 'dist\HexiKeys.exe'
    if (Test-Path -LiteralPath $packagedApp -PathType Leaf) {
        Start-Process -FilePath $packagedApp -WorkingDirectory $appDirectory
        return
    }
    if (-not (Test-Path -LiteralPath $runtimePython)) {
        $basePython = Get-Command python -ErrorAction SilentlyContinue
        if (-not $basePython) { throw 'Python is needed for this source version. Install the standalone HexiKeys release or install Python, then try again.' }
        New-Item -ItemType Directory -Path $runtimeDirectory -Force | Out-Null
        & $basePython.Source -m venv $runtimeDirectory
        if ($LASTEXITCODE -ne 0) { throw 'Could not prepare the private HexiKeys runtime.' }
    }

    $requiredVersion = (Get-Content -LiteralPath $requirements | Where-Object { $_ -match '^cryptography==' } | Select-Object -First 1) -replace '^cryptography==', ''
    $installedVersion = & $runtimePython -c 'import cryptography; print(cryptography.__version__)' 2>$null
    if ($LASTEXITCODE -ne 0 -or $installedVersion.Trim() -ne $requiredVersion) {
        & $runtimePython -m pip install --disable-pip-version-check -r $requirements
        if ($LASTEXITCODE -ne 0) { throw 'Could not install the required encryption library. Check your internet connection and try again.' }
    }

    Start-Process -FilePath $runtimePythonWindowed -ArgumentList ('"' + (Join-Path $appDirectory 'app.py') + '"') -WorkingDirectory $appDirectory
} catch {
    Show-LaunchError $_.Exception.Message
}
