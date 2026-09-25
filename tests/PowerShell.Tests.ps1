BeforeAll {
    $ErrorActionPreference = 'Stop'
    $root = Split-Path -Parent $PSScriptRoot
}
Describe 'PowerShell entrypoints' {
    It 'parses every PS1 without syntax errors' {
        $errors = @()
        Get-ChildItem (Join-Path $root 'scripts') -Filter '*.ps1' | ForEach-Object {
            $tokens = $null; $parseErrors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
            $errors += $parseErrors
        }
        $errors.Count | Should -Be 0
    }
    It 'Control-Center propagates a failing exit code' {
        $originalPath = $env:PATH
        $originalErrorActionPreference = $ErrorActionPreference
        try {
            $env:PATH = ''
            $ErrorActionPreference = 'Continue'
            & $env:ComSpec /c (Join-Path $root 'Control-Center.cmd') *> $null
            $exitCode = $LASTEXITCODE
            $exitCode | Should -Not -Be 0
        }
        finally {
            $env:PATH = $originalPath
            $ErrorActionPreference = $originalErrorActionPreference
        }
    }
}
