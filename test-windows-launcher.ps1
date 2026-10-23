$ErrorActionPreference = 'Stop'
$base = $PSScriptRoot
$scratch = Join-Path $base ('windows-test-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $scratch)
$oldSsh = $env:SSH_BIN
$oldArguments = $env:P2S_ARGUMENTS
$oldPayload = $env:P2S_PAYLOAD
$oldExitCode = $env:P2S_EXIT_CODE

function Invoke-Launcher([string[]]$Arguments) {
    # Use the real Windows PowerShell 5.1 host, independent of the test runner's
    # PowerShell edition. UTF-8 on both pipe ends makes Unicode assertions real.
    $runner = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $runner)) { throw 'Windows PowerShell 5.1 is required for these tests.' }
    $scriptPath = (Join-Path $base 'p2s-harden.ps1').Replace("'", "''")
    $quotedArguments = ($Arguments | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }) -join ' '
    $command = @"
`$ProgressPreference = 'SilentlyContinue'
if (`$PSVersionTable.PSVersion.Major -ne 5 -or `$PSVersionTable.PSVersion.Minor -lt 1) { throw 'Expected Windows PowerShell 5.1.' }
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding(`$false)
`$OutputEncoding = [Console]::OutputEncoding
& '$scriptPath' $quotedArguments
exit `$LASTEXITCODE
"@
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $runner
    $info.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' +
        [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $info.StandardErrorEncoding = New-Object System.Text.UTF8Encoding($false)
    $child = New-Object System.Diagnostics.Process
    $child.StartInfo = $info
    [void]$child.Start()
    $stdout = $child.StandardOutput.ReadToEndAsync()
    $stderr = $child.StandardError.ReadToEndAsync()
    if (-not $child.WaitForExit(15000)) {
        $child.Kill()
        $child.Dispose()
        throw 'Windows launcher test exceeded its 15-second deadline.'
    }
    $result = [PSCustomObject]@{ ExitCode = $child.ExitCode; Stdout = $stdout.Result; Stderr = $stderr.Result }
    $child.Dispose()
    return $result
}

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
        int exitCode;
        return int.TryParse(Environment.GetEnvironmentVariable("P2S_EXIT_CODE"), out exitCode) ? exitCode : 17;
    }
}
'@
    $env:SSH_BIN = $fake
    $env:P2S_ARGUMENTS = Join-Path $scratch 'argv.txt'
    $env:P2S_PAYLOAD = Join-Path $scratch 'payload.py'
    $env:P2S_EXIT_CODE = '17'
    $root = '/srv/a space/it''s a $(literal) "quoted" path\'
    & (Join-Path $base 'p2s-harden.ps1') --ssh 'tester@[::1]' --root $root --json
    if ($LASTEXITCODE -ne 17) { throw 'SSH exit code was not preserved.' }
    $argv = [IO.File]::ReadAllText($env:P2S_ARGUMENTS).Split([char]0)
    if ($argv[-2] -cne 'tester@[::1]') { throw 'SSH target changed.' }
    $quotedRoot = "'" + $root.Replace("'", "'\''") + "'"
    if (-not $argv[-1].Contains("exec python3 -B - '--root' $quotedRoot '--json'")) { throw 'Remote argument quoting changed.' }
    if ([IO.File]::ReadAllText($env:P2S_PAYLOAD) -cne [IO.File]::ReadAllText((Join-Path $base 'p2s_harden.py'))) { throw 'Embedded engine differs from source.' }
    $originalArguments = [IO.File]::ReadAllText($env:P2S_ARGUMENTS)

    $help = Invoke-Launcher @('--help')
    if ($help.ExitCode -ne 0 -or -not $help.Stdout.Contains('Discover and audit')) { throw 'Default English help failed.' }
    if ($help.Stdout.Contains('Voraussetzungen') -or $help.Stderr) { throw 'Default help contains unexpected German or stderr.' }
    $germanCheck = 'Erkennen und pr' + [char]0x00fc + 'fen'
    foreach ($case in @(@('--help', '--lang', 'de'), @('--lang', 'de', '--help'), @('--help', '--lang=de'))) {
        $help = Invoke-Launcher $case
        if ($help.ExitCode -ne 0 -or -not $help.Stdout.Contains($germanCheck)) { throw 'German help or early language selection failed.' }
        if (-not $help.Stdout.Contains([string][char]0x00fc) -or $help.Stdout.Contains([string][char]0x00c3)) { throw 'German Unicode output is mojibake.' }
        if (-not $help.Stdout.Contains('--runtime-dir') -or -not $help.Stdout.Contains('--max-http-probes')) { throw 'German help omits current options.' }
    }
    if ([IO.File]::ReadAllText($env:P2S_ARGUMENTS) -cne $originalArguments) { throw 'Local help unexpectedly invoked SSH.' }

    $missing = Invoke-Launcher @('--json', '--lang', 'de')
    if ($missing.ExitCode -ne 2 -or $missing.Stderr) { throw 'German prerequisite failure is not clean JSON.' }
    $failure = $missing.Stdout | ConvertFrom-Json
    if ($failure.language -cne 'de' -or $failure.findings[0].title -cne 'Voraussetzungen') { throw 'Prerequisite JSON did not retain the selected language.' }
    if (-not $missing.Stdout.Contains([string][char]0x00fc)) { throw 'German prerequisite Unicode was lost.' }
    foreach ($case in @(@('--help', '--lang', 'fr'), @('--lang'))) {
        $invalid = Invoke-Launcher $case
        if ($invalid.ExitCode -ne 2 -or -not $invalid.Stderr.Contains('--lang requires en or de.')) { throw 'Invalid language did not produce an actionable usage error.' }
        if ($invalid.Stdout.Contains('Traceback') -or $invalid.Stderr.Contains('Traceback')) { throw 'Language usage error leaked a traceback.' }
    }

    foreach ($language in @('en', 'de')) {
        $transport = Invoke-Launcher @('--ssh', 'tester@[::1]', '--lang', $language, '--root', $root, '--json')
        if ($transport.ExitCode -ne 17) { throw 'Localized transport changed the SSH exit code.' }
        $argv = [IO.File]::ReadAllText($env:P2S_ARGUMENTS).Split([char]0)
        if ($argv[-2] -cne 'tester@[::1]') { throw 'Localized transport changed the SSH target.' }
        if (-not $argv[-1].Contains("; bootstrap 1 $language || exit 2;")) { throw 'Remote bootstrap did not receive the selected language.' }
        if (-not $argv[-1].Contains("exec python3 -B - '--lang' '$language' '--root' $quotedRoot '--json'")) { throw 'Engine language or native argument quoting changed.' }
        if ([IO.File]::ReadAllText($env:P2S_PAYLOAD) -cne [IO.File]::ReadAllText((Join-Path $base 'p2s_harden.py'))) { throw 'Localized transport altered the embedded UTF-8 engine.' }
    }
    $env:P2S_EXIT_CODE = '255'
    $unreachable = Invoke-Launcher @('--ssh', 'tester@[::1]', '--lang', 'de', '--json')
    if ($unreachable.ExitCode -ne 2) { throw 'Unavailable SSH did not become an incomplete check.' }
    $failure = $unreachable.Stdout | ConvertFrom-Json
    if ($failure.language -cne 'de' -or $failure.findings[0].status -cne 'UNKNOWN' -or
        -not $failure.findings[0].detail.Contains('Ziel nicht erreichbar')) { throw 'SSH failure was not localized, structured JSON.' }
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $base 'p2s-harden.ps1'), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'PowerShell syntax errors.' }
    Write-Output 'PASS Windows PowerShell 5.1: EN/DE help, early language selection, Unicode JSON/errors, native argv with quotes/spaces/backslashes/IPv6, exact UTF-8 payload, bootstrap/engine language forwarding, SSH exit propagation.'
} finally {
    $env:SSH_BIN = $oldSsh
    $env:P2S_ARGUMENTS = $oldArguments
    $env:P2S_PAYLOAD = $oldPayload
    $env:P2S_EXIT_CODE = $oldExitCode
    # Delete only this exact, freshly created test folder beneath the source.
    $resolved = [IO.Path]::GetFullPath($scratch)
    $parent = [IO.Path]::GetFullPath($base).TrimEnd('\') + '\'
    if ($resolved.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase) -and (Split-Path -Leaf $resolved) -match '^windows-test-[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
$global:LASTEXITCODE = 0
