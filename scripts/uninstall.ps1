param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Rest)
& (Join-Path $PSScriptRoot '_invoke.ps1') uninstall @Rest
exit $LASTEXITCODE
