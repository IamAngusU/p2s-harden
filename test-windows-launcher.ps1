$ErrorActionPreference = 'Stop'
$base = $PSScriptRoot
$scratch = Join-Path $base ('windows-test-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $scratch)
$oldSsh = $env:SSH_BIN
$oldArguments = $env:P2S_ARGUMENTS
$oldPayload = $env:P2S_PAYLOAD
try {
    $fake = Join-Path $scratch 'fake ssh.exe'
    Add-Type -OutputAssembly $fake -OutputType ConsoleApplication -TypeDefinition @'
using System;
using System.IO;
using System.Text;
public class FakeSSH {
    public static int Main(string[] args) {
        Console.InputEncoding = new UTF8Encoding(false);
        File.WriteAllText(Environment.GetEnvironmentVariable("P2S_ARGUMENTS"), string.Join("\0", args), new UTF8Encoding(false));
        File.WriteAllText(Environment.GetEnvironmentVariable("P2S_PAYLOAD"), Console.In.ReadToEnd(), new UTF8Encoding(false));
        return 17;
    }
}
'@
    $env:SSH_BIN = $fake
    $env:P2S_ARGUMENTS = Join-Path $scratch 'argv.txt'
    $env:P2S_PAYLOAD = Join-Path $scratch 'payload.py'
    $root = '/srv/a space/it''s a $(literal) "quoted" path\'
    & (Join-Path $base 'p2s-harden.ps1') --ssh 'tester@[::1]' --root $root --json
    if ($LASTEXITCODE -ne 17) { throw 'SSH exit code was not preserved.' }
    $argv = [IO.File]::ReadAllText($env:P2S_ARGUMENTS).Split([char]0)
    if ($argv[-2] -cne 'tester@[::1]') { throw 'SSH target changed.' }
    $quotedRoot = "'" + $root.Replace("'", "'\''") + "'"
    if (-not $argv[-1].Contains("exec python3 -B - '--root' $quotedRoot '--json'")) { throw 'Remote argument quoting changed.' }
    if ([IO.File]::ReadAllText($env:P2S_PAYLOAD) -cne [IO.File]::ReadAllText((Join-Path $base 'p2s_harden.py'))) { throw 'Embedded engine differs from source.' }
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $base 'p2s-harden.ps1'), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'PowerShell syntax errors.' }
    Write-Output 'PASS Windows PowerShell: syntax, native argv with quotes/spaces/backslashes/IPv6, exact UTF-8 payload, SSH exit propagation.'
} finally {
    $env:SSH_BIN = $oldSsh
    $env:P2S_ARGUMENTS = $oldArguments
    $env:P2S_PAYLOAD = $oldPayload
    # Delete only this exact, freshly created test folder beneath the source.
    $resolved = [IO.Path]::GetFullPath($scratch)
    $parent = [IO.Path]::GetFullPath($base).TrimEnd('\') + '\'
    if ($resolved.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $resolved) -match '^windows-test-[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
$global:LASTEXITCODE = 0
