<#
.SYNOPSIS
    Reusable, security-hardened interactive (delegated) sign-in to Microsoft
    Graph. Dot-source this file from any script, then call
    Connect-GraphDelegated with the scopes that script needs.

.DESCRIPTION
    Wraps Connect-MgGraph (Microsoft.Graph.Authentication) with safe defaults
    and positive post-sign-in verification, so every script that uses it gets
    the same login behavior:

      - Clears any existing Graph session in this PowerShell process first,
        so a script never silently reuses a session that belongs to a
        different account, a different tenant, or an app-only identity.
      - Keeps the token cache in memory for this PowerShell process only
        (-ContextScope Process) by default. Tokens are not written to the
        user's on-disk token cache, and closing the window ends the session.
        Use -PersistTokenCache to opt back into the SDK's default on-disk
        cache (-ContextScope CurrentUser).
      - Uses the browser-based interactive flow by default. Device code flow
        is available with -UseDeviceCode for hosts without a browser, but is
        off by default because device code prompts are a common phishing
        vector and many tenants block the flow with Conditional Access.
      - After sign-in, confirms that a session exists, that it is
        Delegated (not app-only), that it landed in the requested tenant
        when a tenant ID GUID was given, and that every requested scope was
        actually granted. A missing scope throws by default, rather than
        letting the calling script continue and fail later with a less
        obvious error.
      - Never accepts, stores, or prints passwords, client secrets, or
        tokens.

.PARAMETER Scopes
    Required. The delegated Microsoft Graph permission scopes the calling
    script needs, e.g. 'User.Read.All','AuditLog.Read.All'. Request only what
    the script actually uses (least privilege).

.PARAMETER TenantId
    Optional. Tenant ID (GUID) or verified domain to sign in to. When a GUID
    is supplied, the resulting session's tenant is verified to match it.

.PARAMETER ClientId
    Optional. Application (client) ID of your own public-client app
    registration to use for delegated sign-in, instead of the Microsoft
    Graph Command Line Tools app. Useful when your tenant restricts which
    apps users can consent to.

.PARAMETER LoginHint
    Optional. UPN to pre-fill in the sign-in prompt (e.g. your admin
    account), reducing the chance of signing in with the wrong account.

.PARAMETER UseDeviceCode
    Optional. Use device code flow instead of the browser flow. Only use this
    on hosts without a browser, and only enter codes you started yourself.

.PARAMETER PersistTokenCache
    Optional. Persist the token cache to the current user's profile
    (-ContextScope CurrentUser) so later sessions can sign in silently.
    Off by default.

.PARAMETER AllowMissingScopes
    Optional. Downgrade "requested scope not granted" from an error to a
    warning. Leave off unless the calling script can tolerate missing
    permissions.

.OUTPUTS
    Microsoft.Graph.PowerShell.Authentication.AuthContext - the verified
    Graph context (same object as Get-MgContext).

.EXAMPLE
    # In your script:
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Connect-GraphDelegated.ps1')

    try {
        $context = Connect-GraphDelegated -Scopes 'User.Read.All' -TenantId 'contoso.onmicrosoft.com'
        # ... Graph calls ...
    }
    finally {
        Disconnect-GraphDelegated
    }

.EXAMPLE
    # Pre-fill the admin account and use a custom app registration
    Connect-GraphDelegated -Scopes 'AuditLog.Read.All','User.Read.All' `
        -LoginHint 'admin@contoso.com' `
        -ClientId '11111111-2222-3333-4444-555555555555'

.NOTES
    Works in PowerShell 7.x and Windows PowerShell 5.1.
    Requires the Microsoft.Graph.Authentication module. This file checks that
    the module is available but does not install it; installation is left to
    the calling script or operator.
    Connect-MgGraph reference:
    https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/connect-mggraph
#>

function Connect-GraphDelegated {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$')]
        [string[]]$Scopes,

        [Parameter()]
        [ValidatePattern('^([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+)$')]
        [string]$TenantId,

        [Parameter()]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$ClientId,

        [Parameter()]
        [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
        [string]$LoginHint,

        [Parameter()]
        [switch]$UseDeviceCode,

        [Parameter()]
        [switch]$PersistTokenCache,

        [Parameter()]
        [switch]$AllowMissingScopes
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
        throw "The Microsoft.Graph.Authentication module is not installed. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
    }
    Import-Module -Name 'Microsoft.Graph.Authentication' -ErrorAction Stop

    # Start from a clean slate so an existing session (other account, other
    # tenant, or app-only) can never be silently reused.
    if (Get-MgContext -ErrorAction SilentlyContinue) {
        Write-Verbose 'Clearing the existing Microsoft Graph session in this process before signing in.'
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }

    $requestedScopes = @($Scopes | Select-Object -Unique)
    $connectParams = @{
        Scopes       = $requestedScopes
        ContextScope = if ($PersistTokenCache) { 'CurrentUser' } else { 'Process' }
        NoWelcome    = $true
    }
    if ($TenantId)      { $connectParams['TenantId'] = $TenantId }
    if ($ClientId)      { $connectParams['ClientId'] = $ClientId }
    if ($LoginHint)     { $connectParams['LoginHint'] = $LoginHint }
    if ($UseDeviceCode) {
        $connectParams['UseDeviceCode'] = $true
        Write-Warning 'Device code sign-in: only enter a code you started yourself, at https://microsoft.com/devicelogin.'
    }

    Write-Verbose ("Signing in to Microsoft Graph (delegated, token cache: {0}) requesting scopes: {1}" -f $connectParams['ContextScope'], ($requestedScopes -join ', '))
    Connect-MgGraph @connectParams

    # --- Positive verification: nothing is assumed from a successful call. ---
    $context = Get-MgContext
    if (-not $context) {
        throw 'Sign-in did not produce a Microsoft Graph session.'
    }

    if ([string]$context.AuthType -ne 'Delegated') {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        throw "Expected a Delegated session but got '$($context.AuthType)'. Disconnected."
    }

    if ($TenantId -and $TenantId -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' -and
        $context.TenantId -ne $TenantId) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        throw "Signed in to tenant '$($context.TenantId)' but '$TenantId' was requested. Disconnected."
    }

    $grantedScopes = @($context.Scopes)
    $missingScopes = @($requestedScopes | Where-Object { $scope = $_; -not ($grantedScopes | Where-Object { $_ -ieq $scope }) })
    if ($missingScopes.Count -gt 0) {
        $message = "The signed-in session is missing requested scope(s): $($missingScopes -join ', '). An administrator may need to grant consent for these permissions."
        if ($AllowMissingScopes) {
            Write-Warning $message
        }
        else {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            throw "$message Disconnected."
        }
    }

    Write-Verbose "Signed in as $($context.Account) to tenant $($context.TenantId)."
    return $context
}

function Disconnect-GraphDelegated {
    <#
        Ends the Microsoft Graph session if one exists. Safe to call from a
        finally block whether or not sign-in succeeded.
    #>
    [CmdletBinding()]
    param()

    if (Get-MgContext -ErrorAction SilentlyContinue) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Verbose 'Disconnected from Microsoft Graph.'
    }
}

# Running this file directly (instead of dot-sourcing it) would define the
# functions in a scope that disappears immediately, so point that out.
if ($MyInvocation.InvocationName -ne '.') {
    Write-Warning "Connect-GraphDelegated.ps1 defines functions and should be dot-sourced: . '$PSCommandPath'"
}
