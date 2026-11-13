<#
.SYNOPSIS
  Creates the Entra ID app registration used by office-smtprelay.

.DESCRIPTION
  - Creates an app registration (single tenant) and its service principal.
  - Grants the Microsoft Graph application permission Mail.Send (admin consent), unless -SkipConsent.
  - Creates a client secret and prints tenant ID, client ID and secret ONCE.
  Nothing is written to disk. See docs/entra-setup.md for the manual steps and
  for the optional Exchange RBAC scoping (not done by this script).

.PARAMETER DisplayName
  Name of the app registration. Default: office-smtprelay

.PARAMETER SecretMonths
  Lifetime of the client secret in months (1-24). Default: 12

.PARAMETER SkipConsent
  Do not grant admin consent for Mail.Send (use when you scope the app with Exchange RBAC instead).

.EXAMPLE
  .\Setup-EntraApp.ps1 -SecretMonths 12
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$DisplayName = 'office-smtprelay',
    [ValidateRange(1, 24)][int]$SecretMonths = 12,
    [switch]$SkipConsent
)

$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Applications

Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All' -NoWelcome
$ctx = Get-MgContext
Write-Host "Signed in as $($ctx.Account) on tenant $($ctx.TenantId)" -ForegroundColor Cyan

# Refuse to create a duplicate
$existing = Get-MgApplication -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Warning "An app registration named '$DisplayName' already exists (appId $($existing[0].AppId))."
    Write-Warning "Use -DisplayName for another name, or manage the existing app in the portal. Nothing was changed."
    Disconnect-MgGraph | Out-Null
    return
}

# Locate the Mail.Send application role on the Microsoft Graph service principal
$graphAppId = '00000003-0000-0000-c000-000000000000'
$graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"
$mailSendRole = $graphSp.AppRoles | Where-Object { $_.Value -eq 'Mail.Send' -and $_.AllowedMemberTypes -contains 'Application' }
if (-not $mailSendRole) { throw 'Could not find the Mail.Send application role on Microsoft Graph.' }

if (-not $PSCmdlet.ShouldProcess("tenant $($ctx.TenantId)", "Create app '$DisplayName'" + $(if ($SkipConsent) { '' } else { ' and grant Mail.Send' }))) { return }

$app = New-MgApplication -DisplayName $DisplayName -SignInAudience 'AzureADMyOrg' `
    -RequiredResourceAccess @(@{
        ResourceAppId  = $graphAppId
        ResourceAccess = @(@{ Id = $mailSendRole.Id; Type = 'Role' })
    })
$sp = New-MgServicePrincipal -AppId $app.AppId
Write-Host "Created app '$DisplayName' (appId $($app.AppId))." -ForegroundColor Green

if ($SkipConsent) {
    Write-Host 'Skipped admin consent (-SkipConsent). Grant it in the portal or scope the app with Exchange RBAC.' -ForegroundColor Yellow
}
else {
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id `
        -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $mailSendRole.Id | Out-Null
    Write-Host 'Granted admin consent for Mail.Send (application).' -ForegroundColor Green
}

$secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
    DisplayName = 'office-smtprelay'
    EndDateTime = (Get-Date).AddMonths($SecretMonths)
}

Write-Host "`n=========== Copy these values now; the secret cannot be shown again ===========" -ForegroundColor Yellow
Write-Host "Tenant ID                    : $($ctx.TenantId)"
Write-Host "Application (client) ID      : $($app.AppId)"
Write-Host "Service principal object ID  : $($sp.Id)   (needed for the optional Exchange RBAC scoping)"
Write-Host "Client secret (value)        : $($secret.SecretText)"
Write-Host "Secret expires               : $($secret.EndDateTime.ToString('yyyy-MM-dd'))"
Write-Host "===============================================================================`n" -ForegroundColor Yellow

Disconnect-MgGraph | Out-Null
