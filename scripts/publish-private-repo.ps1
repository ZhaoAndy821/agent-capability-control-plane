param(
  [string]$Name = 'agent-capability-control-plane',
  [string]$Description = 'Private personal Codex Agent Capability Control Plane'
)
$ErrorActionPreference='Stop'
if(-not (Get-Command gh -ErrorAction SilentlyContinue)){ throw 'GitHub CLI (gh) is required.' }
if(-not (Test-Path (Join-Path $PSScriptRoot '..\.git'))){ throw 'Run inside the initialized V2.1 repository.' }
& gh auth status
if($LASTEXITCODE -ne 0){ exit $LASTEXITCODE }
$root=Resolve-Path (Join-Path $PSScriptRoot '..')
Push-Location $root
try {
  & gh repo create $Name --private --source . --remote origin --push --description $Description
  exit $LASTEXITCODE
} finally { Pop-Location }
