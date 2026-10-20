# Export-SmsMfaUsageReport.ps1

Exports a CSV report of Entra ID users, **members and guests**, who **completed MFA using SMS (text message)** in the last 30 days (configurable 1–30), based on Microsoft Graph sign-in logs.

Place these two files in the same folder:

- `Export-SmsMfaUsageReport.ps1`: the report
- `Connect-GraphDelegated.ps1`: the shared interactive sign-in helper used by the other Entra scripts (required for interactive runs)

## What it measures

The script reads `GET /beta/auditLogs/signIns` for the window, follows every `@odata.nextLink` page, and counts a sign-in as SMS MFA when its `authenticationDetails` contain a step where:

- `authenticationMethod` = `Text message`
- `succeeded` = `true`
- the step is the multifactor step (not `Primary authentication`)

The beta endpoint is required. In Graph v1.0, sign-in records don't include `authenticationDetails` or `userType`, so the method used and the guest/member label can't be determined there.

### Guests

Guests aren't filtered out at any point. Every sign-in in the window is checked, whether it came from a member or a B2B guest. Each user is labeled from the sign-in's `userType`. If that field is missing, the script compares `homeTenantId` with your tenant, so a guest is never counted as a member.

- **Guest UPNs appear in their home format**, for example `adelevance@fabrikam.com`, not `..._fabrikam.com#EXT#@contoso.com`. That's how Entra stores them in sign-in logs. `UserId` is the guest's object ID in your tenant.
- **Guest SMS use only appears if MFA happened in your tenant.** If your cross-tenant access settings trust the guest's home-tenant MFA, the guest completes MFA at home. Your logs then show no SMS step, so those guests won't appear.

Passwordless SMS sign-in (SMS as the primary factor) is excluded by default, since it isn't MFA. Add `-IncludePrimarySms` to include it.

This measures **actual usage**, not registration. A user who registered a phone but never got an SMS prompt won't appear. Sign-ins where MFA was satisfied by an existing token claim have no SMS step, so they aren't counted.

## Output

| File | Contents |
|---|---|
| `SmsMfaUsage_<timestamp>.csv` | One row per member or guest: `UserPrincipalName`, `DisplayName`, `UserType` (Member/Guest), `UserId`, `HomeTenantId`, `CrossTenantAccessType`, `SmsMfaSignIns`, `FirstSmsMfaUtc`, `LastSmsMfaUtc`, `Applications` (sorted by count, highest first) |
| `SmsMfaUsage_<timestamp>_summary.csv` | `UniqueUsersUsingSmsMfa`, `MembersUsingSmsMfa`, `GuestsUsingSmsMfa`, `UnknownTypeUsingSmsMfa`, `TotalSmsMfaSignIns`, `SignInsScanned`, `GuestSignInsScanned`, window start/end, pages read |

The headline number ("how many users") is `UniqueUsersUsingSmsMfa` in the summary file, split into members and guests. It's also printed to the console.

## Prerequisites

- PowerShell 7.x (recommended) or Windows PowerShell 5.1
- `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`
- Entra ID P1 or P2 (you need it for sign-in log access through Graph)
- Permission: **`AuditLog.Read.All`** (read-only)
  - Delegated: the signed-in user also needs a directory role that can read sign-in logs. Reports Reader, Security Reader, or Global Reader will work.
  - App-only: grant the `AuditLog.Read.All` **application** permission with admin consent, and add a certificate credential.

## Usage

Interactive sign-in (default). This uses the shared `Connect-GraphDelegated.ps1`, the same sign-in the other Entra scripts use:

```powershell
./Export-SmsMfaUsageReport.ps1 -TenantId <tenant-guid> -LoginHint admin@contoso.com
```

The helper opens a browser sign-in and keeps tokens in memory for this PowerShell window only. It clears any earlier Graph session first. It stops if the session isn't delegated, is in the wrong tenant, or is missing `AuditLog.Read.All`. Device-code sign-in isn't used.

Unattended (app-only, certificate from `Cert:\CurrentUser\My`). Supply both values to switch to this mode; the helper file isn't needed:

```powershell
./Export-SmsMfaUsageReport.ps1 -TenantId <tenant-guid> `
    -ClientId <app-guid> -CertificateThumbprint <40-hex-thumbprint> `
    -OutputPath C:\Reports\SmsMfa.csv
```

Other options: `-Days 7` for a shorter window, `-IncludePrimarySms`, `-Verbose`.

## Security controls

- **No secrets:** only interactive browser sign-in (via the shared helper) or certificate auth. The script doesn't accept, store, or print client secrets, passwords, or tokens, and it doesn't use device-code flow.
- **Least privilege:** requests only `AuditLog.Read.All` and makes GET calls only.
- **Session hygiene:** it clears any existing Graph session first and uses `-ContextScope Process`. It always disconnects in a `finally` block.
- **Tenant pinning:** it aborts if the connected tenant doesn't match `-TenantId`. In delegated mode it also aborts if the scope wasn't granted.
- **Token containment:** it refuses to follow any pagination link outside `https://graph.microsoft.com/`.
- **Data minimization:** raw sign-in records are processed in memory and never written to disk. Masked phone numbers and IP addresses aren't exported.
- **Output protection:** files are created with owner-only permissions (Windows ACL with inheritance removed, or `chmod 600` on macOS/Linux) before any data is written.
- **CSV injection guard:** values that start with `= + - @` are prefixed with `'`.
- **Resilience:** retries 429/5xx responses, honoring `Retry-After` and backing off exponentially. On 401/403 it stops right away with a clear permissions message.
- **Input validation:** GUID checks on the tenant and client IDs, a hex check on the thumbprint, and a 1–30 range on days.

## Notes

- Entra keeps sign-in logs for 30 days, so 30 is the maximum window.
- Large tenants may produce millions of sign-ins in 30 days. The Graph `signIns` endpoint doesn't support server-side filtering on `authenticationDetails`, so every sign-in in the window is scanned. Expect long runtimes and some throttling. Use a shorter `-Days` for a quick check.
- For recurring reporting at very large scale, consider streaming sign-in logs to Log Analytics and querying `SigninLogs` with KQL.

## Changelog

- **v2:**
  - Interactive sign-in now uses the shared `Connect-GraphDelegated.ps1`, and `-LoginHint` was added.
  - App-only mode is chosen by supplying `-ClientId` together with `-CertificateThumbprint`, matching the other Entra scripts. `-AuthMode` was removed.
  - Guests are included and labeled, with new `UserType`, `HomeTenantId` and `CrossTenantAccessType` columns and member/guest counts in the summary.
  - Switched to the beta sign-in endpoint. v1.0 doesn't return `authenticationDetails`, so v1 of this script would have found no SMS use.
- **v1:** initial release.
