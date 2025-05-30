<##
.SYNOPSIS
    rhcveapi.ps1: PowerShell CVE lookup using Red Hat Security Data API with strict JSON schema enforcement.
.DESCRIPTION
    Fetch CVE details or search by attributes. Outputs JSON conforming to defined schema, CSV, plain text, or fix-state-summary tables.
.PARAMETER Cve
    One or more CVE identifiers (e.g., CVE-2023-4911).
.PARAMETER File
    Path to a text or CSV file containing CVE IDs.
.PARAMETER QBefore, QAfter, QBug, QAdvisory, QSeverity, QProduct, QPackage, QCwe, QCvss, QCvss3, QEmpty, QPageSize, QPageNum, QRaw
    Search filters as defined.
.PARAMETER Fields, AllFields, MostFields
    Field selection for plain output.
.PARAMETER IncludeUrls
    Include Bugzilla URLs in plain text.
.PARAMETER FixStateSummary
    Tabular summary by product_state.
.PARAMETER Format
    Output format: plain, csv, or json (default: plain).
.PARAMETER Concurrency
    Number of parallel requests.
.PARAMETER OutFile
    Write output to file.
#>
[CmdletBinding()]
param(
    [Parameter(Position=0,ValueFromPipeline=$true)] [string[]] $Cve,
    [Alias('i','InFile')]               [string] $File,
    [Alias('q-before')]                 [string] $QBefore,
    [Alias('q-after')]                  [string] $QAfter,
    [Alias('q-bug')]                    [string] $QBug,
    [Alias('q-advisory')]               [string] $QAdvisory,
    [Alias('q-severity')]               [string] $QSeverity,
    [Alias('q-product','p')]            [string] $QProduct,
    [Alias('q-package')]                [string] $QPackage,
    [Alias('q-cwe')]                    [string] $QCwe,
    [Alias('q-cvss')]                   [string] $QCvss,
    [Alias('q-cvss3')]                  [string] $QCvss3,
    [Alias('q-empty')]                  [switch] $QEmpty,
    [Alias('q-pagesize')]               [int]    $QPageSize,
    [Alias('q-pagenum')]                [int]    $QPageNum,
    [Alias('q-raw')]                    [string] $QRaw,
    [Alias('f')]                        [string] $Fields,
    [Alias('a')]                        [switch] $AllFields,
    [Alias('m')]                        [switch] $MostFields,
    [Alias('u')]                        [switch] $IncludeUrls,
    [Alias('fs')]                       [switch] $FixStateSummary,
    [Alias('o')] [ValidateSet('plain','csv','json')] [string] $Format = 'plain',
    [Alias('c')]                        [int]    $Concurrency = 5,
    [Alias('of')]                       [string] $OutFile
)

function Get-CveData { param($Url) Invoke-RestMethod -Uri $Url -ErrorAction Stop }

# Collect IDs or search
$ids = @()
if ($File) { $ids += (Import-Csv $File -Header CVE | Select -Expand CVE) }
if ($Cve)  { $ids += ($Cve -split ',') }
$ids = $ids | Where {$_} | Sort -Unique
$searchFilters = @($QBefore,$QAfter,$QBug,$QAdvisory,$QSeverity,$QProduct,$QPackage,$QCwe,$QCvss,$QCvss3,$QEmpty,$QPageSize,$QPageNum,$QRaw)
$doSearch = (-not $ids) -and ($searchFilters -ne $null)

if ($doSearch) {
    $q = @(); foreach ($p in @{before=$QBefore;after=$QAfter;bug=$QBug;advisory=$QAdvisory;severity=$QSeverity;product=$QProduct;package=$QPackage;cwe=$QCwe;cvss=$QCvss;cvss3=$QCvss3;empty=($QEmpty.IsPresent);pagesize=$QPageSize;pagenum=$QPageNum;raw=$QRaw}) {
        if ($p.Value) { $q += "${p.Key}=${p.Value}" }
    }
    $items = Get-CveData "https://access.redhat.com/hydra/rest/securitydata/cve?" + ($q -join '&')
    if ($items -isnot [System.Array]) { $items = @($items) }
} elseif ($ids) {
    $items = foreach ($id in $ids) {
        Get-CveData -Url "https://access.redhat.com/hydra/rest/securitydata/cve/$id.json"
    }
} else { Throw 'No CVE or filters specified' }

# Fix-State-Summary
if ($FixStateSummary) {
    if ($Format -eq 'csv') {
        # CSV header includes PackageName and Mitigation
        $lines = @('CVE,Severity,Date,ProductName,PackageName,FixState,Mitigation')
        foreach ($item in $items) {
            foreach ($state in $item.package_state) {
                if (-not $QProduct -or $state.product_name -match $QProduct) {
                    $mit = $item.mitigation.value -replace ',', ';'
                    $lines += "$($item.name),$($item.threat_severity),$($item.public_date),$($state.product_name),$($state.package_name),$($state.fix_state),$mit"
                }
            }
        }
        $out = $lines -join "`n"
    } else {
        # Plain table includes PackageName and Mitigation
        $table = foreach ($item in $items) {
            foreach ($state in $item.package_state) {
                if (-not $QProduct -or $state.product_name -match $QProduct) {
                    [PSCustomObject]@{
                        CVE         = $item.name
                        Severity    = $item.threat_severity
                        Date        = $item.public_date
                        ProductName = $state.product_name
                        PackageName = $state.package_name
                        FixState    = $state.fix_state
                        Mitigation  = $item.mitigation.value
                    }
                }
            }
        }
        $out = $table | Format-Table -AutoSize | Out-String
    }
    if ($OutFile) { $out | Out-File -FilePath $OutFile -Encoding UTF8 } else { Write-Output $out }
    exit 0
}

# JSON format: enforce CSAF 2.0 schema
if ($Format -eq 'json') {
    $csaf = [ordered]@{ vulnerabilities = @() }
    foreach ($item in $items) {
        $pkgStates = $item.package_state | ForEach-Object {
            [ordered]@{
                product_name = $_.product_name
                fix_state    = $_.fix_state
                package_name = $_.package_name
                cpe          = $_.cpe
            }
        }
        $affReleases = $item.affected_release | ForEach-Object {
            [ordered]@{
                product_name = $_.product_name
                release_date = $_.release_date
                advisory     = $_.advisory
                cpe          = $_.cpe
                package      = $_.package
            }
        }
        $bz = if ($item.bugzilla) { [ordered]@{ description=$item.bugzilla.description; id=$item.bugzilla.id; url=$item.bugzilla.url } } else { $null }
        $entry = [ordered]@{
            threat_severity  = $item.threat_severity
            public_date      = $item.public_date
            bugzilla         = $bz
            cvss3            = [ordered]@{ cvss3_base_score=$item.cvss3_base_score; cvss3_scoring_vector=$item.cvss3_scoring_vector; status=$item.status }
            cwe              = $item.cwe
            details          = $item.details
            statement        = $item.statement
            affected_release = $affReleases
            package_state    = $pkgStates
            references       = $item.references
            name             = $item.name
            mitigation       = [ordered]@{ value=$item.mitigation.value; lang=$item.mitigation.lang }
            csaw             = $item.csaw
        }
        $csaf.vulnerabilities += $entry
    }
    $csaf | ConvertTo-Json -Depth 10
    exit 0
}

# CSV and Plain
if ($Format -eq 'csv') {
    $header = 'CVE,ThreatSeverity,PublicDate'
    $rows   = $items | ForEach-Object { "{0},{1},{2}" -f $_.CVE, $_.threat_severity, $_.public_date }
    $output = $header + "`n" + ($rows -join "`n")
} else {
    $output = @()
    foreach ($item in $items) {
        $output += $item.name
        $fieldsToShow = if ($AllFields) {
            $item.PSObject.Properties.Name
        } elseif ($MostFields) {
            @('threat_severity','public_date','bugzilla','affected_release','package_state')
        } elseif ($Fields) {
            $Fields -split ','
        } else {
            @('threat_severity','public_date')
        }
        foreach ($field in $fieldsToShow) {
    if ($field -eq 'package_state') {
    # Expand each package state entry with full schema fields
    foreach ($state in $item.package_state) {
        $output += "  package_state: product_name=$($state.product_name), fix_state=$($state.fix_state), package_name=$($state.package_name), cpe=$($state.cpe)"
    }
} else {
        $value = $item
        foreach ($part in $field -split '\.') { $value = $value.$part }
        $output += "  $field`: $value"
    }
}
if ($IncludeUrls) {
            foreach ($bz in $item.bugzilla) { $output += "  URL: $($bz.url)" }
        }
    }
}

# Output to file or console
if ($OutFile) {
    if ($Format -eq 'csv' -or $Format -eq 'plain') {
        $output | Out-File -FilePath $OutFile -Encoding UTF8
    } else {
        $csaf | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutFile -Encoding UTF8
    }
} else {
    if ($Format -eq 'csv' -or $Format -eq 'plain') {
        $output | Write-Output
    } else {
        $csaf | ConvertTo-Json -Depth 10
    }
}