param(
    [switch]$Vault,
    [string]$Project = '.',
    [ValidateSet('project','user')][string]$Scope = 'project'
)
if ($Vault) {
    if ($PSBoundParameters.ContainsKey('Project') -or $PSBoundParameters.ContainsKey('Scope')) {
        Write-Error '-Vault cannot be combined with -Project or -Scope'
        exit 2
    }
    & (Join-Path $PSScriptRoot '_invoke.ps1') audit
} else {
    & (Join-Path $PSScriptRoot '_invoke.ps1') status --project $Project --scope $Scope
}
exit $LASTEXITCODE
