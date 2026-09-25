param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Rest)
& (Join-Path $PSScriptRoot '_invoke.ps1') doctor @Rest
exit $LASTEXITCODE
