# Setup cours Securite Python : Python 3.12 + Poetry + dependances (PowerShell)
$ErrorActionPreference = "Stop"

function Refresh-Path {
    $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [Environment]::GetEnvironmentVariable("Path","User")
}

function Find-Python {
    # Ignore le faux "python" du Microsoft Store (WindowsApps)
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 -c "import sys" 2>$null
        if ($LASTEXITCODE -eq 0) { return @{exe="py"; args=@("-3")} }
    }
    $p = Get-Command python -ErrorAction SilentlyContinue
    if ($p -and $p.Source -notlike "*WindowsApps*") { return @{exe=$p.Source; args=@()} }
    return $null
}

$py = Find-Python
if (-not $py) {
    Write-Host "Python introuvable : installation de Python 3.12 via winget..."
    winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements
    Refresh-Path
    $py = Find-Python
    if (-not $py) { throw "Python installe mais pas detecte : ferme et rouvre PowerShell, puis relance le script." }
}
Write-Host "Python OK :" (& $py.exe @($py.args) --version)

if (-not (Get-Command poetry -ErrorAction SilentlyContinue)) {
    Write-Host "Installation de Poetry..."
    (Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | & $py.exe @($py.args) -
    $env:Path += ";$env:APPDATA\Python\Scripts"
}
$pyExe = (& $py.exe @($py.args) -c "import sys; print(sys.executable)").Trim()
Write-Host "Python utilise :" $pyExe

function Step($label, [scriptblock]$cmd) {
    & $cmd
    if ($LASTEXITCODE -ne 0) { throw "Echec a l'etape : $label" }
}

Step "poetry --version" { poetry --version }
Step "config venv"      { poetry config virtualenvs.in-project true }
# Retire le faux python du Store du PATH de cette session
$env:Path = ($env:Path -split ";" | Where-Object { $_ -notlike "*WindowsApps*" }) -join ";"
# Cree le venv avec le vrai Python et force Poetry a l'utiliser
if (Test-Path .venv) { Remove-Item -Recurse -Force .venv }
Step "creation .venv" { & $pyExe -m venv .venv }
$env:VIRTUAL_ENV = (Resolve-Path .venv).Path
$env:Path = "$env:VIRTUAL_ENV\Scripts;$env:Path"
Step "poetry install"   { poetry install }
# python-magic a besoin de la DLL libmagic : sous Windows "import magic" se bloque
# sans elle. python-magic-bin embarque la DLL. Inutile sous Linux/Exegol.
Step "libmagic (windows)" { & "$env:VIRTUAL_ENV\Scripts\python.exe" -m pip install python-magic-bin }
Step "pytest"           { poetry run pytest -q }
Write-Host "OK - lance le TP avec : poetry run tp1"
