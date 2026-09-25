param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Rest)
& (Join-Path $PSScriptRoot '_invoke.ps1') deactivate @Rest
exit $LASTEXITCODE
