param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Args)
$ErrorActionPreference = 'Stop'
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command py -ErrorAction SilentlyContinue }
if (-not $python) { Write-Error 'Python 3 is required.'; exit 127 }
$cli = Join-Path $PSScriptRoot 'accp.py'
if ($python.Name -eq 'py.exe') { & $python.Source -3 $cli @Args } else { & $python.Source $cli @Args }
exit $LASTEXITCODE
