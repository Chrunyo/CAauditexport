#Requires -Version 5.1

<#
.SYNOPSIS
    Diagnoses why Export-CaAuditLog.ps1 might be skipping CA audit events.
    Read-only: it changes nothing, it just reports what the exporter sees.

.PARAMETER OutputDirectory
    The same -OutputDirectory you pass to the exporter, so this can inspect the
    checkpoint. Optional — omit if you just want to probe the log.

.PARAMETER LogName
    Defaults to 'Security'.

.PARAMETER EventId
    Defaults to the AD CS range 4868..4898.

.EXAMPLE
    .\Test-CaAuditQuery.ps1 -OutputDirectory 'D:\CAAudit'
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$LogName = 'Security',
    [int[]]$EventId = (4868..4898)
)

$ErrorActionPreference = 'Stop'

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

# 1) Am I able to read the Security log at all?
Section 'Access check'
try {
    $probe = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
    Write-Host "OK - can read '$LogName'. Newest overall RecordID = $($probe.RecordId), TimeCreated = $($probe.TimeCreated)"
} catch {
    Write-Host "FAILED to read '$LogName': $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "-> Run elevated / as SYSTEM / as a member of 'Event Log Readers'." -ForegroundColor Yellow
    return
}

# 2) Is CA auditing even turned on?
Section 'CA audit configuration'
try {
    $filterVal = (& certutil.exe -getreg CA\AuditFilter) 2>$null | Out-String
    if ($filterVal -match 'AuditFilter REG_DWORD = ([0-9a-fx]+)') {
        Write-Host "CA AuditFilter = $($matches[1])  (0 = auditing OFF; 127 = all events)"
    } else {
        Write-Host "Could not read CA\AuditFilter (is this the CA server? is certutil present?)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "certutil not available or CA not installed here." -ForegroundColor Yellow
}

# 3) How many CA events actually exist in the log, and how old are they?
# NOTE: query by EventID range (2 expressions), NOT a FilterHashtable Id array.
# The event-log query limit is 23 expressions; the 31-ID CA range 4868..4898
# exceeds it and silently matches NOTHING via -FilterHashtable Id. A range
# query avoids that; we post-filter for any non-contiguous -EventId subset.
Section 'CA events present in the log'
$minId = ($EventId | Measure-Object -Minimum).Minimum
$maxId = ($EventId | Measure-Object -Maximum).Maximum
$xpath = "*[System[(EventID>=$minId and EventID<=$maxId)]]"
$all = @()
try {
    $all = @(Get-WinEvent -LogName $LogName -FilterXPath $xpath -ErrorAction Stop |
        Where-Object { $EventId -contains $_.Id })
} catch {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Host "ZERO events with IDs $minId..$maxId in '$LogName'." -ForegroundColor Red
        Write-Host "-> Either auditing is off (see above) or you're looking at a different log." -ForegroundColor Yellow
    } else { throw }
}

if ($all.Count -gt 0) {
    $oldest = $all[-1]; $newest = $all[0]
    Write-Host "Total CA events: $($all.Count)"
    Write-Host "Oldest: RecordID $($oldest.RecordId)  @ $($oldest.TimeCreated)  (Id $($oldest.Id))"
    Write-Host "Newest: RecordID $($newest.RecordId)  @ $($newest.TimeCreated)  (Id $($newest.Id))"
    Write-Host ("Age of oldest event: {0:N1} hours" -f ((Get-Date) - $oldest.TimeCreated).TotalHours)
    Write-Host "`nBreakdown by Event ID:"
    $all | Group-Object Id | Sort-Object Name |
        Format-Table @{n='EventID';e={$_.Name}}, Count -AutoSize | Out-Host
}

# 4) What does the checkpoint say the exporter will skip?
Section 'Checkpoint state'
$stateFile = if ($OutputDirectory) { Join-Path $OutputDirectory 'CaAuditExport.state.json' } else { $null }
if ($stateFile -and (Test-Path -LiteralPath $stateFile)) {
    $cp = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
    Write-Host "Checkpoint found: LastRecordID = $($cp.LastRecordId), LastTimeCreated = $($cp.LastTimeCreated)"
    Write-Host "-> The exporter will SKIP every CA event with RecordID <= $($cp.LastRecordId)." -ForegroundColor Yellow
    if ($all.Count -gt 0) {
        $wouldExport = @($all | Where-Object { [long]$_.RecordId -gt [long]$cp.LastRecordId })
        Write-Host "-> With this checkpoint, next run would export $($wouldExport.Count) event(s)."
        if ($wouldExport.Count -eq 0) {
            Write-Host "   All existing CA events are already past the checkpoint. Delete the state file to re-baseline." -ForegroundColor Yellow
        }
    }
} elseif ($stateFile) {
    Write-Host "No checkpoint at '$stateFile' -> next run is a FIRST run."
    Write-Host "-> First run only looks back -InitialLookbackHours (default 24h)." -ForegroundColor Yellow
    if ($all.Count -gt 0) {
        $within24 = @($all | Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-24) })
        Write-Host "-> Events within the default 24h window: $($within24.Count) of $($all.Count)."
        if ($within24.Count -eq 0) {
            Write-Host "   >>> This is almost certainly your problem: all CA events are older than 24h." -ForegroundColor Red
            Write-Host "   >>> Fix: run the exporter with a larger -InitialLookbackHours (e.g. 720 for 30 days)." -ForegroundColor Green
        }
    }
} else {
    Write-Host "No -OutputDirectory given; skipping checkpoint inspection."
}

Section 'Summary'
Write-Host "If CA events exist above but the exporter reports none, compare their"
Write-Host "timestamps/RecordIDs against the checkpoint and first-run window shown above."
