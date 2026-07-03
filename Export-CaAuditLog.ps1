#Requires -Version 5.1

<#
.SYNOPSIS
    Incrementally exports Active Directory Certificate Services (AD CS) audit
    events from the Windows Security log to durable files before log recycling
    (wrap/overwrite) removes them.

.DESCRIPTION
    The AD CS Certificate Authority service writes its audit events to the
    Windows *Security* event log under the "Certification Services" task
    category, Event IDs 4868-4898. The Security log has a finite size and
    overwrites the oldest records once it fills, so on a busy CA these audit
    records can be lost within hours or days.

    This script is designed to be run repeatedly (e.g. every 15 minutes) as a
    Windows Scheduled Task. On each run it:

      1. Reads a small JSON checkpoint file recording the last exported record.
      2. Queries the Security log for CA audit events newer than that
         checkpoint (or, on the first run, back InitialLookbackHours hours).
      3. Writes the new events to a timestamped, immutable output file
         (CSV, JSON, or native EVTX).
      4. Advances and saves the checkpoint so the next run picks up exactly
         where this one stopped - no gaps, no duplicates.
      5. Optionally prunes exported files older than RetentionDays.

    The checkpoint tracks both the last EventRecordID and its TimeCreated so
    that a Security-log *clear* (which resets EventRecordID to 1) is detected
    and handled by falling back to a time-based query instead of silently
    skipping every event.

    Requirements
    ------------
    * Must run with rights to read the Security log: run the task as SYSTEM,
      or as an account that is a member of the local "Event Log Readers" group.
    * EVTX output additionally shells out to wevtutil.exe (in-box on Windows).

.PARAMETER OutputDirectory
    Folder where export files and the checkpoint are written. Created if it
    does not exist. Use a path with restricted ACLs for audit integrity.

.PARAMETER OutputFormat
    Csv (default), Json, or Evtx. EVTX preserves full event fidelity and can be
    re-opened in Event Viewer; CSV/JSON are easier to ingest into a SIEM.

.PARAMETER LogName
    Event log to read. Defaults to 'Security'.

.PARAMETER EventId
    Event IDs to export. Defaults to the AD CS Certification Services range
    4868-4898.

.PARAMETER InitialLookbackHours
    On the very first run (no checkpoint yet) look back this many hours.
    Default 24. Ignored once a checkpoint exists.

.PARAMETER StateFile
    Path to the checkpoint JSON file. Defaults to
    <OutputDirectory>\CaAuditExport.state.json.

.PARAMETER MaxEvents
    Optional safety cap on the number of events pulled in a single run.
    0 (default) means no cap.

.PARAMETER RetentionDays
    If greater than 0, export files older than this many days are deleted at
    the end of a successful run. 0 (default) keeps everything.

.EXAMPLE
    .\Export-CaAuditLog.ps1 -OutputDirectory 'D:\CAAudit' -OutputFormat Evtx

    Runs once, exporting new CA audit events to a native .evtx file.

.EXAMPLE
    Register a scheduled task that runs every 15 minutes as SYSTEM:

    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\Scripts\Export-CaAuditLog.ps1" -OutputDirectory "D:\CAAudit" -OutputFormat Evtx -RetentionDays 400'
    $trigger  = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration ([TimeSpan]::MaxValue)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName 'Export-CA-AuditLog' -Action $action `
        -Trigger $trigger -Principal $principal -Settings $settings

.NOTES
    Author : GreyCorbel SSD PKI Automation
    Events : https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4868
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [ValidateSet('Csv', 'Json', 'Evtx')]
    [string]$OutputFormat = 'Csv',

    [ValidateNotNullOrEmpty()]
    [string]$LogName = 'Security',

    [ValidateNotNullOrEmpty()]
    [int[]]$EventId = (4868..4898),

    [ValidateRange(1, 8760)]
    [int]$InitialLookbackHours = 24,

    [switch]$BackfillAll,

    [string]$StateFile,

    [ValidateRange(0, [int]::MaxValue)]
    [int]$MaxEvents = 0,

    [ValidateRange(0, 3650)]
    [int]$RetentionDays = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Helpers ---------------------------------------------------------------

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$ts] [$Level] $Message"
    # Append to the rolling operational log FIRST, so the record survives even
    # if the console stream write below is terminating.
    try {
        Add-Content -LiteralPath $script:OperationLog -Value $line -Encoding UTF8
    } catch {
        # Never let logging failures abort the export itself.
    }
    # Emit to the appropriate stream. Force non-terminating so the caller keeps
    # control of flow (we do explicit throws where a hard stop is intended).
    switch ($Level) {
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Error $Message -ErrorAction Continue }
        default { Write-Verbose $Message -Verbose }
    }
}

function Get-Checkpoint {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Log "Checkpoint file '$Path' is unreadable/corrupt ($($_.Exception.Message)); treating as first run." -Level WARN
        return $null
    }
}

function Save-Checkpoint {
    param([string]$Path, [long]$LastRecordId, [datetime]$LastTimeCreated)
    $state = [pscustomobject]@{
        LastRecordId    = $LastRecordId
        LastTimeCreated = $LastTimeCreated.ToString('o')
        LastRunUtc      = (Get-Date).ToUniversalTime().ToString('o')
        Computer        = $env:COMPUTERNAME
    }
    # Write atomically: temp file then move, so a crash mid-write cannot leave
    # a truncated checkpoint that would force a re-export or a gap.
    $tmp = "$Path.tmp"
    $state | ConvertTo-Json | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

# --- Setup -----------------------------------------------------------------

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path

if (-not $StateFile) {
    $StateFile = Join-Path $OutputDirectory 'CaAuditExport.state.json'
}
$script:OperationLog = Join-Path $OutputDirectory 'CaAuditExport.operations.log'

Write-Log "=== CA audit export starting on $env:COMPUTERNAME (format=$OutputFormat, log=$LogName) ==="

# --- Determine the incremental query window --------------------------------

$checkpoint = Get-Checkpoint -Path $StateFile

# Peek at the newest record currently in the log so we can detect a log clear
# (EventRecordID reset). If the newest available record is *lower* than our
# stored checkpoint, the log was cleared and record numbering restarted.
$newestRecordId = $null
try {
    $newest = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
    $newestRecordId = [long]$newest.RecordId
} catch {
    Write-Log "Could not read newest record from '$LogName': $($_.Exception.Message)" -Level WARN
}

$lastRecordId = 0L
$startTime    = $null

if ($null -ne $checkpoint -and $checkpoint.PSObject.Properties['LastRecordId']) {
    $lastRecordId = [long]$checkpoint.LastRecordId
    $lastTime     = [datetime]::Parse($checkpoint.LastTimeCreated).ToUniversalTime()

    if ($null -ne $newestRecordId -and $newestRecordId -lt $lastRecordId) {
        # Log was cleared/reset since last run -> RecordID filter is unsafe.
        Write-Log "Newest RecordID ($newestRecordId) < checkpoint ($lastRecordId): Security log appears to have been cleared. Falling back to time-based query since $($lastTime.ToString('o'))." -Level WARN
        $lastRecordId = 0L
        $startTime    = $lastTime
    } else {
        # Rewind the time window slightly and rely on RecordID de-duplication
        # to guarantee we never miss or repeat an event on the boundary.
        $startTime = $lastTime.AddSeconds(-2)
    }
} elseif ($BackfillAll) {
    # First run, no time floor: capture every matching event still in the log.
    $startTime = $null
    Write-Log 'No checkpoint and -BackfillAll set; exporting ALL matching events currently in the log.'
} else {
    $startTime = (Get-Date).ToUniversalTime().AddHours(-$InitialLookbackHours)
    Write-Log "No usable checkpoint; first run looking back $InitialLookbackHours hour(s) to $($startTime.ToString('o')). Use -BackfillAll to capture older events."
}

# --- Query the log ---------------------------------------------------------

$filter = @{
    LogName = $LogName
    Id      = $EventId
}
# Only bound by time when we have a floor; a null StartTime means "everything".
if ($null -ne $startTime) { $filter['StartTime'] = $startTime }

$events = @()
try {
    $getParams = @{ FilterHashtable = $filter; ErrorAction = 'Stop' }
    if ($MaxEvents -gt 0) { $getParams['MaxEvents'] = $MaxEvents }

    $events = Get-WinEvent @getParams |
        Where-Object { [long]$_.RecordId -gt $lastRecordId } |
        Sort-Object RecordId
} catch [System.Exception] {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Log 'No new CA audit events since last run.'
    } else {
        Write-Log "Query failed: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

$events = @($events)
if ($events.Count -eq 0) {
    Write-Log 'Nothing to export; checkpoint unchanged. Done.'
    return
}

$minRec = [long]($events[0].RecordId)
$maxRec = [long]($events[-1].RecordId)
Write-Log "Found $($events.Count) new event(s), RecordID $minRec..$maxRec."

# --- Export ----------------------------------------------------------------

$stamp    = (Get-Date).ToString('yyyyMMdd_HHmmss')
$baseName = "CAAudit_{0}_{1}" -f $env:COMPUTERNAME, $stamp

switch ($OutputFormat) {

    'Evtx' {
        # Highest fidelity: export the exact record range with wevtutil so the
        # file re-opens in Event Viewer with all binary/UserData intact.
        $outFile = Join-Path $OutputDirectory "$baseName.evtx"
        $idClause = '(' + (($EventId | ForEach-Object { "EventID=$_" }) -join ' or ') + ')'
        $query = "*[System[$idClause and (EventRecordID>=$minRec) and (EventRecordID<=$maxRec)]]"

        & wevtutil.exe epl $LogName $outFile "/q:$query" /ow:true
        if ($LASTEXITCODE -ne 0) {
            throw "wevtutil epl failed with exit code $LASTEXITCODE."
        }
        Write-Log "Exported EVTX -> $outFile"
    }

    default {
        # Flatten to a stable, SIEM-friendly shape.
        $records = foreach ($e in $events) {
            [pscustomobject]@{
                RecordId      = [long]$e.RecordId
                TimeCreated   = $e.TimeCreated.ToUniversalTime().ToString('o')
                EventId       = $e.Id
                Level         = $e.LevelDisplayName
                Task          = $e.TaskDisplayName
                Provider      = $e.ProviderName
                Computer      = $e.MachineName
                UserId        = if ($e.UserId) { $e.UserId.Value } else { $null }
                Message       = ($e.Message -replace '\r?\n', ' | ')
            }
        }

        if ($OutputFormat -eq 'Json') {
            $outFile = Join-Path $OutputDirectory "$baseName.json"
            $records | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $outFile -Encoding UTF8
        } else {
            $outFile = Join-Path $OutputDirectory "$baseName.csv"
            $records | Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8
        }
        Write-Log "Exported $($records.Count) record(s) -> $outFile"
    }
}

# --- Advance the checkpoint only after a successful export ------------------

Save-Checkpoint -Path $StateFile -LastRecordId $maxRec -LastTimeCreated $events[-1].TimeCreated.ToUniversalTime()
Write-Log "Checkpoint advanced to RecordID $maxRec."

# --- Optional retention pruning --------------------------------------------

if ($RetentionDays -gt 0) {
    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    $old = Get-ChildItem -LiteralPath $OutputDirectory -File -Filter 'CAAudit_*' |
        Where-Object { $_.LastWriteTime -lt $cutoff }
    foreach ($f in $old) {
        try {
            Remove-Item -LiteralPath $f.FullName -Force
            Write-Log "Pruned old export: $($f.Name)"
        } catch {
            Write-Log "Failed to prune $($f.Name): $($_.Exception.Message)" -Level WARN
        }
    }
}

Write-Log '=== CA audit export finished ==='
