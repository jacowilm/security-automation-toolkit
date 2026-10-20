#Requires -Version 5.1
#Requires -RunAsAdministrator

# Export-SecurityEvents.ps1
#
# Defines the Export-SecurityEvents function. Dot-source the file, then call it:
#
#     . .\Export-SecurityEvents.ps1
#     Export-SecurityEvents -Hours 48 -OutputPath C:\Temp\events.csv
#
# Windows only. Reading the Security log needs an elevated (administrator)
# PowerShell session, which the #Requires line above enforces when the file loads.

function Export-SecurityEvents {
    <#
    .SYNOPSIS
    Exports selected Windows Security log events to a CSV file for triage.

    .DESCRIPTION
    Queries the local Security event log with Get-WinEvent -FilterHashtable for
    the requested event IDs over the last N hours, pulls the interesting fields
    out of each event's XML (account, source IP, workstation, logon type) and
    writes one CSV row per event.

    Default event IDs:
      4624  An account was successfully logged on
      4625  An account failed to log on
      4672  Special privileges assigned to a new logon
      4720  A user account was created
      4732  A member was added to a security-enabled local group

    Values that start with = + - or @ are prefixed with an apostrophe so a
    spreadsheet does not treat attacker-controlled text (a failed-logon user
    name, for example) as a formula.

    If no events match, a warning is written and no file is created.

    .PARAMETER Hours
    How far back to look, in hours. Default 24. Allowed range 1 to 8760.

    .PARAMETER EventId
    One or more Security event IDs to export.
    Default 4624, 4625, 4672, 4720, 4732.

    .PARAMETER OutputPath
    CSV file to write (an existing file is overwritten). Default is
    SecurityEvents_<timestamp>.csv in the current directory. Missing parent
    folders are created.

    .EXAMPLE
    Export-SecurityEvents

    Exports the default event IDs from the last 24 hours to a timestamped CSV
    in the current directory.

    .EXAMPLE
    Export-SecurityEvents -Hours 72 -EventId 4625 -OutputPath C:\Temp\failed-logons.csv

    Exports only failed logons from the last three days.

    .EXAMPLE
    Export-SecurityEvents -Hours 6 -WhatIf

    Shows what would be written without creating a file.

    .OUTPUTS
    System.IO.FileInfo for the CSV that was written, or nothing if no events
    were found.

    .NOTES
    Requires Windows PowerShell 5.1 or later and an elevated session.
    Read-only against the event log; the only thing it writes is the CSV.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Position = 0)]
        [ValidateRange(1, 8760)]
        [int]$Hours = 24,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1, 65535)]
        [int[]]$EventId = @(4624, 4625, 4672, 4720, 4732),

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = (Join-Path -Path (Get-Location).Path -ChildPath ('SecurityEvents_{0:yyyyMMdd_HHmmss}.csv' -f (Get-Date)))
    )

    begin {
        $logonTypeNames = @{
            2  = 'Interactive'
            3  = 'Network'
            4  = 'Batch'
            5  = 'Service'
            7  = 'Unlock'
            8  = 'NetworkCleartext'
            9  = 'NewCredentials'
            10 = 'RemoteInteractive'
            11 = 'CachedInteractive'
        }

        # Combine domain and user into DOMAIN\user, tolerating missing parts.
        $joinAccount = {
            param($Domain, $User)
            if ([string]::IsNullOrEmpty($User)) { return '' }
            if ([string]::IsNullOrEmpty($Domain) -or $Domain -eq '-') { return $User }
            return ('{0}\{1}' -f $Domain, $User)
        }

        # Event XML uses "-" for "not applicable".
        $cleanValue = {
            param($Value)
            if ($null -eq $Value -or $Value -eq '-') { return '' }
            return [string]$Value
        }

        # Neutralise CSV formula injection.
        $safeCsv = {
            param($Value)
            if ([string]::IsNullOrEmpty($Value)) { return '' }
            if ($Value -match '^[=+\-@\t\r]') { return ("'" + $Value) }
            return $Value
        }
    }

    process {
        $startTime = (Get-Date).AddHours(-$Hours)
        $filter = @{
            LogName   = 'Security'
            Id        = $EventId
            StartTime = $startTime
        }

        Write-Verbose ('Querying the Security log for event IDs {0} since {1:o}' -f ($EventId -join ', '), $startTime)

        try {
            $winEvents = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
        }
        catch {
            # Get-WinEvent throws (rather than returning nothing) when no event matches.
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
                Write-Warning ('No events found in the Security log for event IDs {0} in the last {1} hour(s). No file was written.' -f ($EventId -join ', '), $Hours)
                return
            }
            throw
        }

        Write-Verbose ('Retrieved {0} event(s); extracting fields from event XML.' -f $winEvents.Count)

        $rows = @(foreach ($winEvent in $winEvents) {
            $data = @{}
            $xml = [xml]$winEvent.ToXml()
            foreach ($node in $xml.Event.EventData.Data) {
                $name = $node.GetAttribute('Name')
                if ($name) { $data[$name] = $node.InnerText }
            }

            $subject = & $joinAccount $data['SubjectDomainName'] $data['SubjectUserName']
            $account = & $joinAccount $data['TargetDomainName'] $data['TargetUserName']
            $details = ''

            switch ($winEvent.Id) {
                4624 {
                    $details = 'AuthPackage={0}' -f (& $cleanValue $data['AuthenticationPackageName'])
                }
                4625 {
                    $details = 'Status={0} SubStatus={1}' -f (& $cleanValue $data['Status']), (& $cleanValue $data['SubStatus'])
                }
                4672 {
                    $account = $subject
                    $details = 'Privileges={0}' -f ((& $cleanValue $data['PrivilegeList']) -replace '\s+', ' ')
                }
                4720 {
                    $details = 'Account created by {0}' -f $subject
                }
                4732 {
                    $member = & $cleanValue $data['MemberName']
                    if ([string]::IsNullOrEmpty($member)) { $member = & $cleanValue $data['MemberSid'] }
                    $account = $member
                    $details = "Added to group '{0}' ({1})" -f (& $cleanValue $data['TargetUserName']), (& $cleanValue $data['TargetSid'])
                }
            }

            $logonType = & $cleanValue $data['LogonType']
            $logonTypeName = ''
            if ($logonType -match '^\d+$' -and $logonTypeNames.ContainsKey([int]$logonType)) {
                $logonTypeName = $logonTypeNames[[int]$logonType]
            }

            [pscustomobject]@{
                TimeCreated    = $winEvent.TimeCreated.ToString('o')
                EventId        = $winEvent.Id
                Account        = & $safeCsv $account
                SubjectAccount = & $safeCsv $subject
                SourceIp       = & $safeCsv (& $cleanValue $data['IpAddress'])
                Workstation    = & $safeCsv (& $cleanValue $data['WorkstationName'])
                LogonType      = $logonType
                LogonTypeName  = $logonTypeName
                Details        = & $safeCsv $details
            }
        })

        $outputDir = Split-Path -Path $OutputPath -Parent
        if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
            if ($PSCmdlet.ShouldProcess($outputDir, 'Create output directory')) {
                New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            }
        }

        if ($PSCmdlet.ShouldProcess($OutputPath, ('Write {0} event(s) to CSV' -f $rows.Count))) {
            $rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
            Write-Verbose ('Wrote {0} row(s) to {1}' -f $rows.Count, $OutputPath)
            Get-Item -LiteralPath $OutputPath
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Write-Warning 'This file only defines Export-SecurityEvents. Dot-source it first (". .\Export-SecurityEvents.ps1"), then run Export-SecurityEvents.'
}
