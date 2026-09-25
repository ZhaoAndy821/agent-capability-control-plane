param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Rest)
& (Join-Path $PSScriptRoot '_invoke.ps1') activate @Rest
exit $LASTEXITCODE
