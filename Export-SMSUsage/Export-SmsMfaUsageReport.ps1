<#
.SYNOPSIS
    Exports a CSV report of members AND guests who completed MFA with SMS (text message)
    in the last N days (default 30).

.DESCRIPTION
    Reads Microsoft Entra ID interactive sign-in logs via Microsoft Graph
    (/beta/auditLogs/signIns - authenticationDetails and userType are only exposed on beta),
    splits the window into short time slices (default 6 h) that are each paged to completion,
    filters server-side to sign-ins that reached the MFA stage, and inspects each sign-in's authenticationDetails for a
    successful "Text message" step used as the multifactor (non-primary) step.

    Guests (B2B) are included in the lookup and in every output. Each user is labeled Member or
    Guest, and guests carry their home tenant ID and cross-tenant access type.

    Outputs:
      1. <OutputPath>                 - one row per user (member or guest) who used SMS MFA
      2. <OutputPath>_summary.csv     - totals: unique users, members, guests, SMS MFA events, window

    Sign-in:
      - Default: interactive delegated sign-in through the shared Connect-GraphDelegated.ps1
        (must be in the same folder as this script), the same helper used by the other Entra scripts.
      - Optional: app-only certificate sign-in when BOTH -ClientId and -CertificateThumbprint are given.

    Security design:
      - No client secrets, passwords, or tokens are accepted, stored, or printed.
      - Least-privilege read-only scopes: AuditLog.Read.All (sign-in logs) and User.Read.All
        (manager name/email; not requested when -SkipManagerLookup is used).
      - Graph session scoped to this process and disconnected in a finally block.
      - Tenant ID of the resulting session is verified against -TenantId.
      - Pagination links are validated to stay on https://graph.microsoft.com before being followed.
      - Output files are created with owner-only permissions before any data is written.
      - CSV values are neutralized against formula/CSV injection.
      - Masked phone numbers and IP addresses are NOT exported.

.PARAMETER TenantId
    Entra tenant ID (GUID). Required so the script cannot silently run against the wrong tenant.
    Also used to recognize guests (home tenant differs from this tenant).

.PARAMETER Days
    Look-back window, 1-30. Entra retains sign-in logs for 30 days (P1/P2).
    If omitted, the script asks how many days to export (Enter = 30). Unattended runs
    (app-only certificate sign-in or -NonInteractive sessions) don't prompt and use 30.

.PARAMETER OutputPath
    Path for the per-user CSV. Defaults to ./SmsMfaUsage_<timestamp>.csv

.PARAMETER LoginHint
    Optional UPN to pre-fill in the interactive sign-in prompt (e.g. your admin account).

.PARAMETER ClientId
    App registration (client) ID for app-only certificate sign-in. Must be used with -CertificateThumbprint.

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate in the CurrentUser\My (or LocalMachine\My) store. Must be used with -ClientId.

.PARAMETER ChunkHours
    Length of each time slice (1-24, default 6). Each slice is paged separately so skip tokens
    don't expire. Slices that still hit an expired skip token are halved and re-read automatically.

.PARAMETER MinChunkMinutes
    Smallest slice size the automatic split will go down to (default 5).

.PARAMETER SkipManagerLookup
    Don't resolve each user's manager name and email. Removes the User.Read.All requirement.

.PARAMETER IncludePrimarySms
    Also count SMS used as the primary (passwordless SMS sign-in) step. Off by default because
    that is not MFA.

.EXAMPLE
    ./Export-SmsMfaUsageReport.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -LoginHint admin@contoso.com

.EXAMPLE
    ./Export-SmsMfaUsageReport.ps1 -TenantId <guid> -ClientId <guid> `
        -CertificateThumbprint ABCDEF0123... -OutputPath C:\Reports\sms.csv
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [ValidateRange(1, 30)]
    [int]$Days,

    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath ("SmsMfaUsage_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))),

    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$LoginHint,

    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$CertificateThumbprint,

    [switch]$IncludePrimarySms,

    # Size of each time slice queried separately. Short slices keep every page chain short so
    # skip tokens don't expire. Slices that still hit an expired skip token are split automatically.
    [ValidateRange(1, 24)]
    [int]$ChunkHours = 6,

    [ValidateRange(1, 60)]
    [int]$MinChunkMinutes = 5,

    # Skip the manager name/email lookup (drops the User.Read.All requirement).
    [switch]$SkipManagerLookup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Enforce TLS 1.2+ on Windows PowerShell 5.1 (PowerShell 7 already negotiates modern TLS).
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

$GraphBase             = 'https://graph.microsoft.com'
$script:RequiredScopes = @('AuditLog.Read.All')
if (-not $SkipManagerLookup) { $script:RequiredScopes += 'User.Read.All' }
$GraphBatchSize        = 20   # Microsoft Graph JSON batching hard limit per request
$SmsMethodName         = 'Text message'   # value Entra writes to authenticationDetails.authenticationMethod
$MaxRetries            = 6

#region Helpers -----------------------------------------------------------------

function Get-Prop {
    # StrictMode-safe property read: Graph omits some properties (e.g. @odata.nextLink on the last page).
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Connect-ReportGraph {
    if ($ClientId -and $CertificateThumbprint) {
        # App-only (unattended). Does not need Connect-GraphDelegated.ps1.
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Host "Connecting to Microsoft Graph using app-only certificate authentication (ClientId: $ClientId)..."
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint `
            -ContextScope Process -NoWelcome
    }
    elseif ($ClientId -or $CertificateThumbprint) {
        throw 'Both -ClientId and -CertificateThumbprint must be supplied together for app-only authentication.'
    }
    else {
        # Interactive delegated sign-in via the shared helper (dot-sourced at script scope below).
        Write-Host 'Connecting to Microsoft Graph using interactive delegated sign-in (shared Connect-GraphDelegated.ps1)...'
        $delegatedParams = @{ Scopes = $script:RequiredScopes; TenantId = $TenantId }
        if ($LoginHint) { $delegatedParams['LoginHint'] = $LoginHint }
        # The helper clears any old session, keeps tokens in memory, and verifies
        # delegated auth type, tenant match, and granted scopes (throws otherwise).
        [void](Connect-GraphDelegated @delegatedParams)
    }

    $ctx = Get-MgContext
    if (-not $ctx) { throw 'Microsoft Graph connection failed.' }
    if ($ctx.TenantId -ne $TenantId) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        throw "Connected tenant ($($ctx.TenantId)) does not match -TenantId ($TenantId). Aborting."
    }

    $who = if ($ctx.Account) { $ctx.Account } else { $ctx.AppName }
    Write-Host ("Connected to tenant {0} as {1} ({2})." -f $ctx.TenantId, $who, $ctx.AuthType)
}

function Invoke-GraphGetWithRetry {
    param([Parameter(Mandatory)][string]$Uri)

    # Never send the bearer token anywhere but Graph.
    if (-not $Uri.StartsWith("$GraphBase/", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to follow non-Graph URI: $Uri"
    }

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        }
        catch {
            $resp   = Get-Prop $_.Exception 'Response'
            $status = if ($resp -and (Get-Prop $resp 'StatusCode')) { [int]$resp.StatusCode } else { 0 }

            $msg = [string]$_.Exception.Message
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg += ' ' + $_.ErrorDetails.Message }
            if ($msg -match 'skip\s*token') {
                # Expired/invalid paging token: signal the caller to restart (and split) this time slice.
                $ex = [System.Exception]::new("Skip token expired or invalid: $msg")
                $ex.Data['SkipTokenExpired'] = $true
                throw $ex
            }

            if ($status -in 401, 403) {
                throw ("Access denied ({0}). Ensure AuditLog.Read.All is consented, the signed-in user holds " +
                       "Reports Reader / Security Reader / Global Reader, and the tenant has Entra ID P1/P2.") -f $status
            }

            $retryable = $status -in 429, 500, 502, 503, 504 -or $status -eq 0
            if (-not $retryable -or $attempt -eq $MaxRetries) { throw }

            $wait = [math]::Min(120, [math]::Pow(2, $attempt))
            try {
                $ra = $resp.Headers.RetryAfter
                if ($ra -and $ra.Delta) { $wait = [math]::Ceiling($ra.Delta.TotalSeconds) }
            } catch { }

            Write-Warning ("Graph returned {0}. Retry {1}/{2} in {3}s." -f $status, $attempt, ($MaxRetries - 1), $wait)
            Start-Sleep -Seconds $wait
        }
    }
}

function New-RestrictedFile {
    # Create (or truncate) the file and restrict it to the current user BEFORE writing data.
    param([Parameter(Mandatory)][string]$Path)

    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -LiteralPath $Path -Value $null -Force

    # $IsWindows only exists on PowerShell 6+; on 5.1 we are always on Windows.
    $onWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or (Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue)
    if (-not $onWindows) {
        & chmod 600 -- $Path
    }
    else {
        $me  = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)   # remove inherited ACEs
        $acl.SetOwner($me)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow')))
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
}

function ConvertTo-SafeCsvValue {
    # Neutralize spreadsheet formula injection (=, +, -, @, tab, CR).
    param($Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    if ($s -match '^[=+\-@\t\r]') { return "'" + $s }
    return $s
}

function Test-IsSmsMfaStep {
    param($Step, [int]$Index)

    if ((Get-Prop $Step 'authenticationMethod') -ne $SmsMethodName) { return $false }
    if ((Get-Prop $Step 'succeeded') -ne $true) { return $false }
    if ($IncludePrimarySms) { return $true }

    $req = [string](Get-Prop $Step 'authenticationStepRequirement')
    if ($req) { return ($req -notmatch 'Primary') }
    return ($Index -gt 0)   # fallback: anything after the first step is a secondary factor
}

function Get-UserTypeLabel {
    # Prefer Graph's userType; fall back to home tenant comparison so guests are never mislabeled.
    param($SignIn)
    $type = [string](Get-Prop $SignIn 'userType')
    if ($type -ieq 'guest')  { return 'Guest' }
    if ($type -ieq 'member') { return 'Member' }
    $homeTenant = [string](Get-Prop $SignIn 'homeTenantId')
    if ($homeTenant -and $homeTenant -ne $TenantId) { return 'Guest' }
    if ($homeTenant) { return 'Member' }
    return 'Unknown'
}

function ConvertTo-UtcDate {
    # Graph timestamps are UTC. Normalize whether the SDK hands back a string or a DateTime.
    param($Value)
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    return [datetimeoffset]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
}

function Format-GraphDate { param([datetime]$Date) $Date.ToString('yyyy-MM-ddTHH:mm:ssZ') }

#endregion ----------------------------------------------------------------------

#region Manager lookup (same approach as Export-SmsVoiceMfaUsers.ps1) -------------

function Invoke-GraphBatchGet {
    <#
        Sends GET requests through Graph JSON batching (POST /$batch, max 20 per call).
        Throttled (429) and 5xx sub-requests are retried in a follow-up batch containing only
        the failed IDs, honoring Retry-After. One failed sub-request never affects the others.
        https://learn.microsoft.com/en-us/graph/json-batching
    #>
    param(
        [Parameter(Mandatory)][array]$Requests,     # @{ Id = <unique>; Url = <relative v1.0 URL> }
        [Parameter(Mandatory)][string]$ActivityName,
        [int]$MaxBatchRetries = 5
    )

    $results = @{}
    if ($Requests.Count -eq 0) { return $results }

    $pending = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Requests) { $pending.Add($r) }
    $total = $pending.Count
    $done = 0
    $attempt = 0

    while ($pending.Count -gt 0) {
        $attempt++
        if ($attempt -gt ($MaxBatchRetries + 1)) {
            foreach ($r in $pending) { $results[$r.Id] = [pscustomobject]@{ Status = -1; Body = $null; Error = 'Exceeded max retries for this batch sub-request.' } }
            break
        }

        $retryQueue = [System.Collections.Generic.List[object]]::new()
        $retryAfter = 0

        for ($i = 0; $i -lt $pending.Count; $i += $GraphBatchSize) {
            $chunk = $pending.GetRange($i, [math]::Min($GraphBatchSize, $pending.Count - $i))
            $body  = @{ requests = @($chunk | ForEach-Object { @{ id = $_.Id; method = 'GET'; url = $_.Url } }) } | ConvertTo-Json -Depth 6

            Write-Progress -Activity $ActivityName -Status ("{0} of {1} resolved (attempt {2})" -f $done, $total, $attempt) -PercentComplete (100 * $done / [math]::Max($total, 1))

            try {
                $response = Invoke-MgGraphRequest -Method POST -Uri "$GraphBase/v1.0/`$batch" -Body $body -ContentType 'application/json' -OutputType PSObject
            }
            catch {
                $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { " | $($_.ErrorDetails.Message)" } else { '' }
                Write-Warning "Batch request failed ($ActivityName): $($_.Exception.Message)$detail"
                foreach ($item in $chunk) { $retryQueue.Add($item) }
                continue
            }

            $answered = @{}
            foreach ($sub in @(Get-Prop $response 'responses')) {
                $reqId  = [string](Get-Prop $sub 'id')
                $status = [int](Get-Prop $sub 'status')
                $item   = $chunk | Where-Object { $_.Id -eq $reqId } | Select-Object -First 1
                if (-not $item) { continue }
                $answered[$reqId] = $true

                if ($status -eq 429 -or $status -ge 500) {
                    $ra = Get-Prop (Get-Prop $sub 'headers') 'Retry-After'
                    $n = 0
                    if ($ra -and [int]::TryParse([string]$ra, [ref]$n)) { $retryAfter = [math]::Max($retryAfter, $n) }
                    $retryQueue.Add($item)
                }
                else {
                    $results[$reqId] = [pscustomobject]@{ Status = $status; Body = (Get-Prop $sub 'body'); Error = $null }
                    $done++
                }
            }
            foreach ($item in $chunk) { if (-not $answered.ContainsKey($item.Id)) { $retryQueue.Add($item) } }
        }

        if ($retryQueue.Count -gt 0 -and $attempt -le $MaxBatchRetries) {
            $wait = if ($retryAfter -gt 0) { $retryAfter } else { [math]::Pow(2, $attempt) }
            Write-Warning ("Throttled on {0} manager lookup(s) (attempt {1}/{2}). Waiting {3}s." -f $retryQueue.Count, $attempt, $MaxBatchRetries, $wait)
            Start-Sleep -Seconds $wait
        }
        $pending = $retryQueue
    }

    Write-Progress -Activity $ActivityName -Completed
    return $results
}

function ConvertTo-ManagerRecord {
    # Returns DisplayName/Mail, or $null when the payload has no usable manager data. Graph returns
    # a manager with only id/@odata.type when the caller can't read that object - treated as unresolved.
    param([AllowNull()]$Payload)
    if ($null -eq $Payload) { return $null }
    $displayName = Get-Prop $Payload 'displayName'
    $mail        = Get-Prop $Payload 'mail'
    if ([string]::IsNullOrWhiteSpace([string]$displayName) -and [string]::IsNullOrWhiteSpace([string]$mail)) { return $null }
    return [pscustomobject]@{ DisplayName = $displayName; Mail = $mail }
}

function Get-GraphErrorSummary {
    param([int]$Status, [AllowNull()]$Body)
    $err     = Get-Prop $Body 'error'
    $code    = Get-Prop $err 'code'
    $message = Get-Prop $err 'message'
    $summary = "HTTP $Status"
    if ($code)    { $summary += " $code" }
    if ($message) { $summary += ": $message" }
    return $summary
}

function Get-ManagerLookup {
    <#
        Resolves manager display name AND email for each user ID (members and guests) via batching.
          1. GET /users/{id}/manager?$select=id,displayName,mail
          2. For anything not positively resolved (other than 404 = no manager), retry via
             GET /users/{id}?$select=id&$expand=manager($select=id,displayName,mail)
        Every failure is reported with its HTTP status / Graph error code, grouped by reason, so a
        permission problem never looks like "no manager".
        https://learn.microsoft.com/en-us/graph/api/user-list-manager
    #>
    param([Parameter(Mandatory)][string[]]$UserIds)

    Write-Host ("Resolving manager name and email for {0} user(s) (batched, up to {1} per request)..." -f $UserIds.Count, $GraphBatchSize)

    $lookup     = @{}
    $noManager  = 0
    $reasons    = @{}
    $unresolved = [System.Collections.Generic.List[string]]::new()
    $select     = 'id,displayName,mail'

    $requests = @($UserIds | ForEach-Object { @{ Id = $_; Url = "/users/$_/manager?`$select=$select" } })
    $results  = Invoke-GraphBatchGet -Requests $requests -ActivityName 'Resolving managers'

    foreach ($id in $UserIds) {
        $r = $results[$id]
        if (-not $r) { $unresolved.Add($id); $reasons[$id] = 'No response returned'; continue }
        if ($r.Status -eq 200) {
            $rec = ConvertTo-ManagerRecord -Payload $r.Body
            if ($rec) { $lookup[$id] = $rec }
            else {
                $unresolved.Add($id)
                $reasons[$id] = "HTTP 200 but manager properties were empty (type: $(Get-Prop $r.Body '@odata.type')) - usually means the caller lacks permission to read that manager object"
            }
        }
        elseif ($r.Status -eq 404) { $noManager++ }
        else {
            $unresolved.Add($id)
            $reasons[$id] = if ($r.Error) { $r.Error } else { Get-GraphErrorSummary -Status $r.Status -Body $r.Body }
        }
    }

    if ($unresolved.Count -gt 0) {
        Write-Warning ("{0} manager lookup(s) not resolved by /users/{{id}}/manager; retrying via `$expand=manager. First reason: {1}" -f $unresolved.Count, $reasons[$unresolved[0]])
        $expandReq = @($unresolved | ForEach-Object { @{ Id = $_; Url = "/users/$_`?`$select=id&`$expand=manager(`$select=$select)" } })
        $expandRes = Invoke-GraphBatchGet -Requests $expandReq -ActivityName 'Resolving managers (fallback)'

        foreach ($id in @($unresolved)) {
            $r = $expandRes[$id]
            if (-not $r) { continue }
            if ($r.Status -eq 200) {
                $mgr = Get-Prop $r.Body 'manager'
                if ($null -eq $mgr) { $noManager++; [void]$unresolved.Remove($id); continue }
                $rec = ConvertTo-ManagerRecord -Payload $mgr
                if ($rec) { $lookup[$id] = $rec; [void]$unresolved.Remove($id) }
            }
            else {
                $fb = if ($r.Error) { $r.Error } else { Get-GraphErrorSummary -Status $r.Status -Body $r.Body }
                $reasons[$id] = "$($reasons[$id]) | fallback: $fb"
            }
        }
    }

    if ($unresolved.Count -gt 0) {
        foreach ($g in ($unresolved | ForEach-Object { $reasons[$_] } | Group-Object | Sort-Object Count -Descending)) {
            Write-Warning ("Manager unresolved for {0} user(s): {1}" -f $g.Count, $g.Name)
        }
        Write-Warning "Unresolved managers are written as '(Not Set)'. If this affects everyone, confirm the session holds User.Read.All. For app-only certificate runs, Microsoft documents the manager API as not supporting application permissions - use interactive sign-in."
    }

    Write-Host ("Manager resolution complete: {0} with a manager, {1} with none, {2} unresolved." -f $lookup.Count, $noManager, $unresolved.Count)
    return $lookup
}

#endregion ----------------------------------------------------------------------


# Load the shared interactive sign-in helper at script scope (only needed for delegated runs,
# so app-only runs don't depend on the file).
if (-not ($ClientId -and $CertificateThumbprint)) {
    $sharedLoginScript = Join-Path -Path $PSScriptRoot -ChildPath 'Connect-GraphDelegated.ps1'
    if (-not (Test-Path -LiteralPath $sharedLoginScript -PathType Leaf)) {
        throw "Interactive sign-in requires Connect-GraphDelegated.ps1 in the same folder as this script ($PSScriptRoot). Copy it there, or use -ClientId and -CertificateThumbprint for app-only sign-in."
    }
    . $sharedLoginScript
}

# Ask how many days to export when -Days wasn't supplied. Prompt before sign-in so the operator
# isn't asked after the browser flow. Never prompt in unattended runs (it would hang a scheduled task).
if (-not $PSBoundParameters.ContainsKey('Days')) {
    $isAppOnly      = [bool]($ClientId -and $CertificateThumbprint)
    $nonInteractive = (-not [Environment]::UserInteractive) -or
                      ([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^-noni(nteractive)?$' })
    if ($isAppOnly -or $nonInteractive) {
        $Days = 30
        Write-Host 'No -Days supplied in an unattended run; using 30 days.'
    }
    else {
        # Separate variable: $Days keeps its [ValidateRange(1,30)] check, so it can't hold a placeholder.
        $chosen = 0
        for ($try = 1; $try -le 3 -and $chosen -eq 0; $try++) {
            $answer = ([string](Read-Host 'How many days of sign-ins do you want to export? (1-30, press Enter for 30)')).Trim()
            $n = 0
            if ($answer -eq '') { $chosen = 30 }
            elseif ($answer -match '^\d{1,2}$' -and [int]::TryParse($answer, [ref]$n) -and $n -ge 1 -and $n -le 30) { $chosen = $n }
            else { Write-Warning 'Please enter a whole number from 1 to 30 (Entra keeps sign-in logs for 30 days).' }
        }
        if ($chosen -eq 0) { throw 'No valid number of days entered. Run again, or pass -Days 1..30.' }
        $Days = $chosen
    }
}
Write-Host ("Exporting SMS MFA usage for the last {0} day(s)." -f $Days)

# Whole-second UTC boundaries so slice edges line up exactly.
$nowUtc      = (Get-Date).ToUniversalTime()
$windowEnd   = [datetime]::new($nowUtc.Ticks - ($nowUtc.Ticks % [TimeSpan]::TicksPerSecond), [DateTimeKind]::Utc)
$windowStart = $windowEnd.AddDays(-$Days)

# Server-side filter: only sign-ins that reached the MFA stage. SMS can only be an MFA step on those,
# so this discards the bulk of the log (single-factor / token-based sign-ins) before it is downloaded.
# Passwordless SMS is single-factor, so the filter is dropped when -IncludePrimarySms is used.
$mfaFilter = if ($IncludePrimarySms) { '' } else { " and authenticationRequirement eq 'multiFactorAuthentication'" }
# No userType filter: members AND guests are both returned and processed.

$users         = @{}   # userId -> aggregate
$scanned       = 0
$scannedGuests = 0
$smsEvents     = 0
$page          = 0
$slicesDone    = 0
$slicesSplit   = 0
$summaryPath   = [IO.Path]::ChangeExtension($OutputPath, $null).TrimEnd('.') + '_summary.csv'

# Build time slices (oldest first). Each slice is [Start, End); Graph only supports ge/le on
# createdDateTime, so we query ge Start / le End and drop anything at exactly End client-side
# (except the final slice), so no sign-in is counted twice at a boundary.
$slices = [System.Collections.Generic.Stack[object]]::new()
$edges  = [System.Collections.Generic.List[datetime]]::new()
for ($t = $windowStart; $t -lt $windowEnd; $t = $t.AddHours($ChunkHours)) { $edges.Add($t) }
$edges.Add($windowEnd)
for ($i = $edges.Count - 2; $i -ge 0; $i--) {
    $slices.Push([pscustomobject]@{ Start = $edges[$i]; End = $edges[$i + 1]; IsLast = ($i -eq $edges.Count - 2); Attempts = 0 })
}
$totalSpan = ($windowEnd - $windowStart).TotalSeconds
$doneSpan  = 0

try {
    Connect-ReportGraph
    $sw = [Diagnostics.Stopwatch]::StartNew()

    while ($slices.Count -gt 0) {
        $slice = $slices.Pop()
        $filter = "createdDateTime ge {0} and createdDateTime le {1}{2}" -f (Format-GraphDate $slice.Start), (Format-GraphDate $slice.End), $mfaFilter
        $uri    = "$GraphBase/beta/auditLogs/signIns?`$filter=$([uri]::EscapeDataString($filter))&`$top=999"

        # Buffer this slice; only commit once every page of it has been read. If the skip token
        # expires mid-slice, the partial buffer is thrown away and the slice is re-read, so counts
        # are never duplicated or partial.
        $hits         = [System.Collections.Generic.List[object]]::new()
        $sliceScanned = 0
        $sliceGuests  = 0
        $slicePages   = 0

        try {
            while ($uri) {
                $slicePages++
                $resp = Invoke-GraphGetWithRetry -Uri $uri

                foreach ($si in @(Get-Prop $resp 'value')) {
                    $when = ConvertTo-UtcDate (Get-Prop $si 'createdDateTime')
                    if (-not $slice.IsLast -and $when -ge $slice.End) { continue }   # belongs to next slice

                    $sliceScanned++
                    $userType = Get-UserTypeLabel -SignIn $si
                    if ($userType -eq 'Guest') { $sliceGuests++ }

                    $details = @(Get-Prop $si 'authenticationDetails')
                    $hit = $false
                    for ($d = 0; $d -lt $details.Count; $d++) {
                        if (Test-IsSmsMfaStep -Step $details[$d] -Index $d) { $hit = $true; break }
                    }
                    if ($hit) { $hits.Add([pscustomobject]@{ SignIn = $si; When = $when; UserType = $userType }) }
                }

                $pct = if ($totalSpan) { [int](100 * $doneSpan / $totalSpan) } else { 0 }
                Write-Progress -Activity 'Reading MFA sign-in logs (members and guests)' -PercentComplete $pct `
                    -Status ("Slice {0} -> {1} | page {2} | scanned {3:N0} | SMS MFA users {4:N0} | {5:hh\:mm\:ss} elapsed" -f `
                        (Format-GraphDate $slice.Start), (Format-GraphDate $slice.End), $slicePages, ($scanned + $sliceScanned), $users.Count, $sw.Elapsed)
                $uri = Get-Prop $resp '@odata.nextLink'
            }
        }
        catch {
            if (-not $_.Exception.Data['SkipTokenExpired']) { throw }

            $spanMin = ($slice.End - $slice.Start).TotalMinutes
            if ($spanMin -gt $MinChunkMinutes) {
                # Split into two halves (whole seconds) and re-read both.
                $midSec = [math]::Floor(($slice.End - $slice.Start).TotalSeconds / 2)
                $mid    = $slice.Start.AddSeconds($midSec)
                Write-Warning ("Skip token expired in slice {0} -> {1} ({2:N0} min). Splitting and re-reading." -f (Format-GraphDate $slice.Start), (Format-GraphDate $slice.End), $spanMin)
                $slices.Push([pscustomobject]@{ Start = $mid;         End = $slice.End; IsLast = $slice.IsLast; Attempts = 0 })
                $slices.Push([pscustomobject]@{ Start = $slice.Start; End = $mid;       IsLast = $false;        Attempts = 0 })
                $slicesSplit++
            }
            elseif ($slice.Attempts -lt 3) {
                $slice.Attempts++
                Write-Warning ("Skip token expired in minimum-size slice {0}; retry {1}/3." -f (Format-GraphDate $slice.Start), $slice.Attempts)
                $slices.Push($slice)
            }
            else {
                throw "Skip token keeps expiring for slice $(Format-GraphDate $slice.Start) -> $(Format-GraphDate $slice.End) even at $MinChunkMinutes minutes. Try a lower -MinChunkMinutes, or check network latency/proxy inspection."
            }
            continue
        }

        # ---- Commit the completed slice ----
        $scanned       += $sliceScanned
        $scannedGuests += $sliceGuests
        $page          += $slicePages
        $slicesDone++
        $doneSpan      += ($slice.End - $slice.Start).TotalSeconds

        foreach ($h in $hits) {
            $si = $h.SignIn
            $smsEvents++
            $userId = Get-Prop $si 'userId'
            $upn    = Get-Prop $si 'userPrincipalName'
            $app    = Get-Prop $si 'appDisplayName'
            $key    = if ($userId) { $userId } else { $upn }

            if (-not $users.ContainsKey($key)) {
                $users[$key] = [ordered]@{
                    UserId                = $userId
                    UserPrincipalName     = $upn
                    DisplayName           = Get-Prop $si 'userDisplayName'
                    UserType              = $h.UserType
                    HomeTenantId          = Get-Prop $si 'homeTenantId'
                    CrossTenantAccessType = Get-Prop $si 'crossTenantAccessType'
                    SmsMfaCount           = 0
                    FirstSmsMfaUtc        = $h.When
                    LastSmsMfaUtc         = $h.When
                    Apps                  = [System.Collections.Generic.HashSet[string]]::new()
                }
            }
            $u = $users[$key]
            $u.SmsMfaCount++
            if ($u.UserType -eq 'Unknown' -and $h.UserType -ne 'Unknown') { $u.UserType = $h.UserType }
            if ($h.When -lt $u.FirstSmsMfaUtc) { $u.FirstSmsMfaUtc = $h.When }
            if ($h.When -gt $u.LastSmsMfaUtc)  { $u.LastSmsMfaUtc  = $h.When }
            if ($app) { [void]$u.Apps.Add([string]$app) }
        }
        Write-Verbose ("Slice {0} -> {1}: {2:N0} sign-ins, {3} SMS MFA, {4} page(s)." -f (Format-GraphDate $slice.Start), (Format-GraphDate $slice.End), $sliceScanned, $hits.Count, $slicePages)
    }
    Write-Progress -Activity 'Reading MFA sign-in logs (members and guests)' -Completed

    # ---- Manager lookup (members and guests) ----
    $managers = @{}
    $managerIds = @($users.Values | Where-Object { $_.UserId -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' } | ForEach-Object { [string]$_.UserId })
    if (-not $SkipManagerLookup -and $managerIds.Count -gt 0) {
        $managers = Get-ManagerLookup -UserIds $managerIds
    }

    # ---- Per-user report (members and guests) ----
    $rows = foreach ($u in $users.Values) {
        [pscustomobject]@{
            UserPrincipalName     = ConvertTo-SafeCsvValue $u.UserPrincipalName
            DisplayName           = ConvertTo-SafeCsvValue $u.DisplayName
            ManagerName           = $(if ($SkipManagerLookup) { '(Skipped)' } elseif ($managers.ContainsKey([string]$u.UserId) -and $managers[[string]$u.UserId].DisplayName) { ConvertTo-SafeCsvValue $managers[[string]$u.UserId].DisplayName } else { '(Not Set)' })
            ManagerEmail          = $(if ($SkipManagerLookup) { '(Skipped)' } elseif ($managers.ContainsKey([string]$u.UserId) -and $managers[[string]$u.UserId].Mail) { ConvertTo-SafeCsvValue $managers[[string]$u.UserId].Mail } else { '(Not Set)' })
            UserType              = $u.UserType
            UserId                = ConvertTo-SafeCsvValue $u.UserId
            HomeTenantId          = ConvertTo-SafeCsvValue $u.HomeTenantId
            CrossTenantAccessType = ConvertTo-SafeCsvValue $u.CrossTenantAccessType
            SmsMfaSignIns         = $u.SmsMfaCount
            FirstSmsMfaUtc        = $u.FirstSmsMfaUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
            LastSmsMfaUtc         = $u.LastSmsMfaUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
            Applications          = ConvertTo-SafeCsvValue (($u.Apps | Sort-Object) -join '; ')
        }
    }

    New-RestrictedFile -Path $OutputPath
    @($rows) | Sort-Object -Property @{ Expression = 'SmsMfaSignIns'; Descending = $true }, @{ Expression = 'UserPrincipalName'; Descending = $false } |
        Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8 -Force

    # ---- Summary ----
    $memberCount  = @($users.Values | Where-Object { $_.UserType -eq 'Member' }).Count
    $guestCount   = @($users.Values | Where-Object { $_.UserType -eq 'Guest' }).Count
    $unknownCount = @($users.Values | Where-Object { $_.UserType -eq 'Unknown' }).Count

    $summary = [pscustomobject]@{
        TenantId                 = $TenantId
        WindowStartUtc           = $windowStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
        WindowEndUtc             = $windowEnd.ToString('yyyy-MM-ddTHH:mm:ssZ')
        DaysCovered              = $Days
        UniqueUsersUsingSmsMfa   = $users.Count
        MembersUsingSmsMfa       = $memberCount
        GuestsUsingSmsMfa        = $guestCount
        UnknownTypeUsingSmsMfa   = $unknownCount
        TotalSmsMfaSignIns       = $smsEvents
        SignInsScanned           = $scanned
        ServerSideMfaFilter      = -not [bool]$IncludePrimarySms
        TimeSlicesRead           = $slicesDone
        TimeSlicesSplit          = $slicesSplit
        RuntimeSeconds           = [int]$sw.Elapsed.TotalSeconds
        GuestSignInsScanned      = $scannedGuests
        UsersWithManager         = $(if ($SkipManagerLookup) { 'Skipped' } else { $managers.Count })
        PagesRead                = $page
        IncludesPrimarySms       = [bool]$IncludePrimarySms
        GeneratedUtc             = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    New-RestrictedFile -Path $summaryPath
    $summary | Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding UTF8 -Force

    Write-Host ''
    Write-Host ("Users who used SMS MFA in the last {0} days: {1:N0}  (members {2:N0}, guests {3:N0})" -f $Days, $users.Count, $memberCount, $guestCount) -ForegroundColor Cyan
    Write-Host ("SMS MFA sign-ins: {0:N0}  |  Sign-ins scanned: {1:N0} (guest sign-ins: {2:N0})" -f $smsEvents, $scanned, $scannedGuests)
    Write-Host ("Time slices: {0} ({1} split after skip-token expiry) | runtime {2:hh\:mm\:ss}" -f $slicesDone, $slicesSplit, $sw.Elapsed)
    Write-Host "Report : $OutputPath"
    Write-Host "Summary: $summaryPath"
}
finally {
    if (Get-Command -Name Disconnect-GraphDelegated -ErrorAction SilentlyContinue) {
        Disconnect-GraphDelegated
    }
    else {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    }
}
