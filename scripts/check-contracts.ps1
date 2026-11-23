#Requires -Version 5.1
<#
.SYNOPSIS
    Validate the interface contract set in contracts/.

.DESCRIPTION
    Checks:
      * no CONTRACTS.md remains anywhere in the working tree
      * every contract file is named C-###.md and its heading declares the same identifier
      * identifiers are unique
      * every contract declares Status, Owner, Auth, Request, at least one Response, Errors and
        Conformance test
      * every status is one of Draft, Frozen, Implemented
      * contracts/README.md indexes every contract exactly once with the same owner, status and
        conformance test, and links to the matching file

    This is the PowerShell counterpart of scripts/check-contracts.

.EXAMPLE
    scripts/check-contracts.ps1

    Exit status is 0 when the contract set is valid and 1 when any check fails.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$contractsDir = Join-Path $repoRoot 'contracts'
$indexPath = Join-Path $contractsDir 'README.md'

$script:failures = 0

function Fail([string]$Message) {
    [Console]::Error.WriteLine("check-contracts: $Message")
    $script:failures++
}

function Test-Status([string]$Value) {
    return $Value -in @('Draft', 'Frozen', 'Implemented')
}

function Read-Contract([string]$Path) {
    $fields = @{
        Status = ''
        Owner = ''
        Auth = ''
        Request = ''
        Errors = ''
        ConformanceTest = ''
    }
    $hasResponse = $false
    $hasErrors = $false
    $heading = $null

    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($null -eq $heading) {
            $heading = $line
            continue
        }
        if ($line -match '^\*\*(?<label>[^*]+):\*\*[ \t]*(?<value>.*)$') {
            $label = $Matches['label']
            $value = $Matches['value'].Trim()
            switch ($label) {
                'Status' { $fields.Status = $value }
                'Owner' { $fields.Owner = $value }
                'Auth' { $fields.Auth = $value }
                'Request' { $fields.Request = $value }
                'Errors' { $hasErrors = $true; $fields.Errors = $value }
                'Conformance test' { $fields.ConformanceTest = $value }
            }
            if ($label -like 'Response*') {
                $hasResponse = $true
            }
        }
    }

    return [pscustomobject]@{
        Heading         = $heading
        Fields          = $fields
        HasResponse     = $hasResponse
        HasErrors       = $hasErrors
    }
}

$rows = New-Object System.Collections.Generic.List[object]
$indexIds = New-Object System.Collections.Generic.HashSet[string]

if (-not (Test-Path -LiteralPath $indexPath -PathType Leaf)) {
    Fail 'contracts/README.md is missing'
}
else {
    foreach ($line in Get-Content -LiteralPath $indexPath) {
        if (-not $line.StartsWith('|')) { continue }
        $cells = @($line.Trim('|').Split('|') | ForEach-Object { $_.Trim() })
        if ($cells.Count -lt 5) { continue }
        if ($cells[0] -notmatch '^\[(?<id>C-\d{3})\]\((?<target>[^)]+)\)$') { continue }

        $id = $Matches['id']
        $target = $Matches['target']
        $owner = $cells[2]
        $status = $cells[3]
        $conformance = $cells[4]

        if ([string]::IsNullOrWhiteSpace($owner) -or [string]::IsNullOrWhiteSpace($status) -or
            [string]::IsNullOrWhiteSpace($conformance)) {
            Fail "contracts/README.md row for $id is missing an owner, status, or conformance test"
            continue
        }
        if (-not (Test-Status $status)) {
            Fail "contracts/README.md row for $id has invalid status '$status'"
        }
        if (-not $indexIds.Add($id)) {
            Fail "contract identifier $id is indexed more than once"
            continue
        }

        $rows.Add([pscustomobject]@{
                Id          = $id
                Target      = $target
                Owner       = $owner
                Status      = $status
                Conformance = $conformance
            })
    }
}

$headings = New-Object System.Collections.Generic.HashSet[string]
$contractCount = 0

foreach ($file in Get-ChildItem -LiteralPath $contractsDir -Filter 'C-*.md' -File) {
    $base = $file.Name

    if ($base -notmatch '^C-\d{3}\.md$') {
        Fail "contract file contracts/$base is not named C-###.md"
        continue
    }

    $id = [IO.Path]::GetFileNameWithoutExtension($base)
    $contractCount++
    $contract = Read-Contract -Path $file.FullName

    if ($null -eq $contract.Heading -or $contract.Heading -notmatch '^# (?<id>C-\d{3}): .+$') {
        Fail "contracts/$base heading is not '# C-###: Title'"
    }
    elseif ($Matches['id'] -ne $id) {
        Fail "$base heading declares $($Matches['id']) but the file is named $id.md"
    }

    if (-not $headings.Add($id)) {
        Fail "contract identifier $id is declared by more than one file"
    }

    foreach ($label in @('Status', 'Owner', 'Auth', 'Request', 'ConformanceTest')) {
        if ([string]::IsNullOrWhiteSpace($contract.Fields[$label])) {
            $name = if ($label -eq 'ConformanceTest') { 'Conformance test' } else { $label }
            Fail "contracts/$base has no $name value"
        }
    }
    if (-not $contract.HasErrors) {
        Fail "contracts/$base has no Errors field"
    }
    if (-not $contract.HasResponse) {
        Fail "contracts/$base has no Response field"
    }
    if ($contract.Fields.Status -and -not (Test-Status $contract.Fields.Status)) {
        Fail "contracts/$base has invalid status '$($contract.Fields.Status)'"
    }

    $row = $rows | Where-Object { $_.Id -eq $id } | Select-Object -First 1
    if ($null -eq $row) {
        Fail "$id is not indexed in contracts/README.md"
        continue
    }

    if ($row.Owner -ne $contract.Fields.Owner) {
        Fail "$id owner is '$($contract.Fields.Owner)' in contracts/$base but '$($row.Owner)' in the index"
    }
    if ($row.Status -ne $contract.Fields.Status) {
        Fail "$id status is '$($contract.Fields.Status)' in contracts/$base but '$($row.Status)' in the index"
    }
    $simple = $contract.Fields.ConformanceTest.Split('.')[-1]
    if ($row.Conformance -ne $contract.Fields.ConformanceTest -and $row.Conformance -ne $simple) {
        Fail "$id conformance test is '$($contract.Fields.ConformanceTest)' in contracts/$base but '$($row.Conformance)' in the index"
    }
}

foreach ($row in $rows) {
    $file = Join-Path $contractsDir "$($row.Id).md"
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        Fail "contracts/README.md indexes $($row.Id) but contracts/$($row.Id).md does not exist"
    }
    elseif ($row.Target -ne "$($row.Id).md") {
        Fail "contracts/README.md links $($row.Id) to $($row.Target) instead of $($row.Id).md"
    }
}

$stale = Get-ChildItem -LiteralPath $repoRoot -Recurse -Force -Filter 'CONTRACTS.md' -File -ErrorAction SilentlyContinue |
    Where-Object {
        $relative = $_.FullName.Substring($repoRoot.Length)
        $relative -notmatch '(^|[\\/])(docs|node_modules|build|\.git|\.gradle)([\\/]|$)'
    }
foreach ($file in $stale) {
    $relative = $file.FullName.Substring($repoRoot.Length).TrimStart('\', '/')
    Fail "CONTRACTS.md still exists: $relative"
}

if ($script:failures -ne 0) {
    [Console]::Error.WriteLine("check-contracts: $($script:failures) problem(s) found")
    exit 1
}

Write-Output "check-contracts: $contractCount contracts valid ($($rows.Count) indexed)"
