param([Parameter(Mandatory=$true)][string]$Target,[switch]$Force)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$template=Join-Path $root 'templates\project'
$targetPath=[IO.Path]::GetFullPath($Target)
New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
$items=@('.codex-skillset.json','AGENTS.md','.codex\agents\project-explorer.toml','.codex\agents\project-worker.toml','.codex\agents\project-reviewer.toml')
foreach($rel in $items){$src=Join-Path $template $rel;$dst=Join-Path $targetPath $rel;if((Test-Path $dst)-and -not $Force){Write-Host "Skip existing: $dst";continue};New-Item -ItemType Directory -Path (Split-Path -Parent $dst) -Force|Out-Null;Copy-Item $src $dst -Force}
