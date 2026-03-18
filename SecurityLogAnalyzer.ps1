# =============================================================================
# Windows Security Log Analyzer
# Author : Blaine Traylor
# Project: Windows Security Log Analysis Lab
# Purpose: Query Windows Event Viewer Security logs, correlate authentication
#          anomalies, flag suspicious privilege escalation, and generate
#          an incident-style summary report.
#
# Prerequisites:
#   - Run as Administrator (required to read Security event log)
#   - Windows PowerShell 5.1+ or PowerShell 7+
#
# Usage:
#   .\SecurityLogAnalyzer.ps1                  # Analyze last 24 hours
#   .\SecurityLogAnalyzer.ps1 -Hours 48        # Analyze last 48 hours
#   .\SecurityLogAnalyzer.ps1 -Hours 24 -Report .\report.txt
# =============================================================================

[CmdletBinding()]
param(
    [int]    $Hours  = 24,
    [string] $Report = "SecurityReport_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"
)

# ─── Configuration ─────────────────────────────────────────────────────────

# Thresholds — tune to environment baselines
$FAILED_LOGON_THRESHOLD   = 5     # Failed logons from one account before flagging
$LOCKOUT_THRESHOLD        = 1     # Any lockout is notable
$PRIV_USE_THRESHOLD       = 3     # Privilege uses before flagging

# MITRE ATT&CK mappings
$MITRE_MAP = @{
    "4625" = "T1110 – Brute Force / Password Guessing"
    "4624" = "T1078 – Valid Accounts"
    "4648" = "T1078 – Valid Accounts (Explicit Credential Use)"
    "4672" = "T1078.002 – Special Privileges Assigned to New Logon"
    "4720" = "T1136 – Create Account"
    "4740" = "T1531 – Account Access Removal (Lockout)"
}

# ─── Helpers ───────────────────────────────────────────────────────────────

function Write-Header($text) {
    Write-Host ""
    Write-Host ("─" * 55) -ForegroundColor DarkCyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host ("─" * 55) -ForegroundColor DarkCyan
}

function Write-Finding($severity, $message) {
    $icons = @{ HIGH = "🔴"; MEDIUM = "🟡"; INFO = "🔵" }
    $colors = @{ HIGH = "Red"; MEDIUM = "Yellow"; INFO = "Cyan" }
    Write-Host "  [$severity] $($icons[$severity])  $message" -ForegroundColor $colors[$severity]
    $script:AllFindings += "[$severity] $message"
}

# ─── Event Queries ─────────────────────────────────────────────────────────

function Get-SecurityEvents($EventId, $HoursBack) {
    $StartTime = (Get-Date).AddHours(-$HoursBack)
    try {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = $EventId
            StartTime = $StartTime
        } -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  [WARN] Could not query Event ID $EventId — may require elevation." -ForegroundColor DarkYellow
        return @()
    }
}

# ─── Analysis Functions ────────────────────────────────────────────────────

function Analyze-FailedLogons {
    Write-Header "Event 4625 — Failed Logon Attempts"

    $events = Get-SecurityEvents -EventId 4625 -HoursBack $Hours
    if (-not $events) {
        Write-Host "  ✅ No failed logon events in the past $Hours hours."
        return
    }

    Write-Host "  Total failed logons: $($events.Count)"

    # Group by target account name
    $byAccount = $events | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $ns  = New-Object Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event")
        $acct = $xml.SelectSingleNode("//e:Data[@Name='TargetUserName']", $ns).'#text'
        $ip   = $xml.SelectSingleNode("//e:Data[@Name='IpAddress']",      $ns).'#text'
        [PSCustomObject]@{ Account = $acct; IP = $ip; Time = $_.TimeCreated }
    } | Group-Object Account | Sort-Object Count -Descending

    foreach ($grp in $byAccount) {
        $count = $grp.Count
        $ips   = ($grp.Group.IP | Sort-Object -Unique) -join ", "
        Write-Host "  Account: $($grp.Name.PadRight(25)) | Failures: $count | IPs: $ips"

        if ($count -ge $FAILED_LOGON_THRESHOLD) {
            Write-Finding "HIGH" "$($grp.Name) — $count failed logons from: $ips → $($MITRE_MAP['4625'])"
        }
    }
}

function Analyze-SuccessfulLogons {
    Write-Header "Event 4624 — Successful Logons"

    $events = Get-SecurityEvents -EventId 4624 -HoursBack $Hours
    if (-not $events) {
        Write-Host "  ✅ No successful logon events found."
        return
    }

    Write-Host "  Total successful logons: $($events.Count)"

    # Flag logon type 10 (RemoteInteractive / RDP) and type 3 (Network)
    $byType = $events | ForEach-Object {
        $xml  = [xml]$_.ToXml()
        $ns   = New-Object Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event")
        $type = $xml.SelectSingleNode("//e:Data[@Name='LogonType']", $ns).'#text'
        $acct = $xml.SelectSingleNode("//e:Data[@Name='TargetUserName']", $ns).'#text'
        [PSCustomObject]@{ Account = $acct; LogonType = $type }
    } | Group-Object LogonType

    foreach ($grp in $byType) {
        $typeLabel = switch ($grp.Name) {
            "2"  { "Interactive (local)" }
            "3"  { "Network (file share / net logon)" }
            "10" { "RemoteInteractive (RDP)" }
            default { "Type $($grp.Name)" }
        }
        Write-Host "  $typeLabel — $($grp.Count) logon(s)"
        if ($grp.Name -eq "10") {
            Write-Finding "MEDIUM" "RDP logons detected ($($grp.Count)) — verify authorized remote access"
        }
    }
}

function Analyze-PrivilegeEscalation {
    Write-Header "Event 4672 — Special Privileges Assigned to New Logon"

    $events = Get-SecurityEvents -EventId 4672 -HoursBack $Hours
    if (-not $events) {
        Write-Host "  ✅ No privilege escalation events found."
        return
    }

    Write-Host "  Total privilege assignment events: $($events.Count)"

    $byAcct = $events | ForEach-Object {
        $xml  = [xml]$_.ToXml()
        $ns   = New-Object Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event")
        $acct = $xml.SelectSingleNode("//e:Data[@Name='SubjectUserName']", $ns).'#text'
        [PSCustomObject]@{ Account = $acct; Time = $_.TimeCreated }
    } | Group-Object Account | Sort-Object Count -Descending

    foreach ($grp in $byAcct) {
        Write-Host "  $($grp.Name.PadRight(30)) | $($grp.Count) events"
        if ($grp.Count -ge $PRIV_USE_THRESHOLD) {
            Write-Finding "MEDIUM" "$($grp.Name) received elevated privileges $($grp.Count)x → $($MITRE_MAP['4672'])"
        }
    }
}

function Analyze-AccountCreation {
    Write-Header "Event 4720 — New User Accounts Created"

    $events = Get-SecurityEvents -EventId 4720 -HoursBack $Hours
    if (-not $events) {
        Write-Host "  ✅ No new account creation events."
        return
    }

    foreach ($evt in $events) {
        $xml  = [xml]$evt.ToXml()
        $ns   = New-Object Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event")
        $newAcct  = $xml.SelectSingleNode("//e:Data[@Name='TargetUserName']",   $ns).'#text'
        $createdBy = $xml.SelectSingleNode("//e:Data[@Name='SubjectUserName']", $ns).'#text'
        Write-Host "  ⚠️  Account '$newAcct' created by '$createdBy' at $($evt.TimeCreated)"
        Write-Finding "HIGH" "New account '$newAcct' created by '$createdBy' → $($MITRE_MAP['4720'])"
    }
}

function Analyze-AccountLockouts {
    Write-Header "Event 4740 — Account Lockouts"

    $events = Get-SecurityEvents -EventId 4740 -HoursBack $Hours
    if (-not $events) {
        Write-Host "  ✅ No account lockout events."
        return
    }

    foreach ($evt in $events) {
        $xml  = [xml]$evt.ToXml()
        $ns   = New-Object Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event")
        $acct = $xml.SelectSingleNode("//e:Data[@Name='TargetUserName']",       $ns).'#text'
        $src  = $xml.SelectSingleNode("//e:Data[@Name='TargetDomainName']",     $ns).'#text'
        Write-Host "  🔒 '$acct' locked out from '$src' at $($evt.TimeCreated)"
        Write-Finding "HIGH" "Account lockout: '$acct' — likely brute-force → $($MITRE_MAP['4740'])"
    }
}

# ─── Report Writer ─────────────────────────────────────────────────────────

function Write-Report {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $lines = @(
        "Windows Security Log Analysis Report",
        "Generated : $timestamp",
        "Window    : Last $Hours hours",
        "Hostname  : $env:COMPUTERNAME",
        "",
        "─── Findings ─────────────────────────────────────────────────"
    )
    $lines += $script:AllFindings
    $lines += @(
        "",
        "─── Summary ──────────────────────────────────────────────────",
        "  Total findings : $($script:AllFindings.Count)",
        "  HIGH           : $(($script:AllFindings | Where-Object { $_ -match '\[HIGH\]' }).Count)",
        "  MEDIUM         : $(($script:AllFindings | Where-Object { $_ -match '\[MEDIUM\]' }).Count)",
        "",
        "─── Methodology ──────────────────────────────────────────────",
        "  Event IDs analyzed: 4624, 4625, 4672, 4720, 4740",
        "  MITRE ATT&CK mappings applied for context.",
        "  Thresholds: Failed logons >= $FAILED_LOGON_THRESHOLD, Lockouts >= $LOCKOUT_THRESHOLD",
        "  Reference: NIST SP 800-92 Guide to Computer Security Log Management"
    )
    $lines | Out-File -FilePath $Report -Encoding UTF8
    Write-Host "`n📄 Report saved to: $Report" -ForegroundColor Green
}

# ─── Main ──────────────────────────────────────────────────────────────────

$script:AllFindings = @()

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Windows Security Log Analyzer                       ║" -ForegroundColor Cyan
Write-Host "║   Blaine Traylor | Security Log Analysis Lab          ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "  Analyzing Security logs for the last $Hours hours..."

Analyze-FailedLogons
Analyze-SuccessfulLogons
Analyze-PrivilegeEscalation
Analyze-AccountCreation
Analyze-AccountLockouts

Write-Host ""
Write-Host ("═" * 55) -ForegroundColor Cyan
Write-Host "  FINDINGS SUMMARY" -ForegroundColor Cyan
Write-Host ("═" * 55) -ForegroundColor Cyan

if ($script:AllFindings.Count -eq 0) {
    Write-Host "  ✅ No significant findings in the analysis window." -ForegroundColor Green
} else {
    $script:AllFindings | ForEach-Object { Write-Host "  $_" }
}

$highCount   = ($script:AllFindings | Where-Object { $_ -match '\[HIGH\]'   }).Count
$mediumCount = ($script:AllFindings | Where-Object { $_ -match '\[MEDIUM\]' }).Count
Write-Host "`n  Total: $($script:AllFindings.Count)  |  🔴 HIGH: $highCount  |  🟡 MEDIUM: $mediumCount`n" -ForegroundColor White

Write-Report
