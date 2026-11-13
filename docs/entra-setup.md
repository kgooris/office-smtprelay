# Microsoft Entra ID setup

`office-smtprelay` sends mail through the Microsoft Graph `sendMail` endpoint using an **app registration** with the **application** permission `Mail.Send` (client credentials flow, no signed-in user). This page explains how to create it and, optionally, how to limit which mailboxes it may send as.

You need:

- A Microsoft 365 tenant with Exchange Online mailboxes.
- An account that can create app registrations and grant admin consent (e.g. *Application Administrator* or *Global Administrator*). For the optional scoping step you also need *Exchange Administrator*.
- No Azure subscription, no extra licence. App registrations are free.

Throughout this guide, `contoso.com` stands for your own domain.

---

## 1. Create the app registration

You can do this [manually](#option-a-manual-portal-steps) or with the [helper script](#option-b-helper-script). The script cannot do the optional Exchange scoping step; see [section 3](#3-recommended-limit-which-mailboxes-the-app-can-send-as).

### Option A: manual (portal steps)

1. Open the [Microsoft Entra admin center](https://entra.microsoft.com) and go to **Entra ID** -> **App registrations** -> **New registration**.
2. Name: `office-smtprelay` (any name works).
   Supported account types: **Accounts in this organizational directory only (Single tenant)**.
   Redirect URI: leave empty. Select **Register**.
3. On the **Overview** page, copy:
   - **Application (client) ID**
   - **Directory (tenant) ID**
4. Go to **API permissions** -> **Add a permission** -> **Microsoft Graph** -> **Application permissions** -> search for `Mail.Send` -> tick it -> **Add permissions**.
   Do **not** add delegated permissions; they do not work for this flow.
5. Select **Grant admin consent for \<your tenant\>** and confirm. The status column must show a green check ("Granted for ...").
6. Go to **Certificates & secrets** -> **Client secrets** -> **New client secret**. Choose a description and an expiry (maximum 24 months; shorter is safer but needs more frequent rotation).
7. **Copy the secret *Value* immediately.** It is shown only once. (Do not copy the *Secret ID*.)

You now have three values for the relay: **tenant ID**, **client ID** and **client secret**.

> The permission `Mail.Send` (application) allows the app to send as **any mailbox in the tenant** until you limit it in [section 3](#3-recommended-limit-which-mailboxes-the-app-can-send-as).

### Option B: helper script

[`scripts/Setup-EntraApp.ps1`](../scripts/Setup-EntraApp.ps1) performs steps 1-7 with Microsoft Graph PowerShell.

```powershell
Install-Module Microsoft.Graph.Applications -Scope CurrentUser   # once
.\scripts\Setup-EntraApp.ps1                      # interactive sign-in
.\scripts\Setup-EntraApp.ps1 -SecretMonths 12     # shorter secret lifetime
.\scripts\Setup-EntraApp.ps1 -SkipConsent         # create app, grant consent yourself in the portal
```

What it does:

- Signs in interactively with the scopes `Application.ReadWrite.All` and `AppRoleAssignment.ReadWrite.All`. You must approve these for your own sign-in.
- Creates the app registration and its service principal.
- Looks up the `Mail.Send` application role on Microsoft Graph and grants admin consent (unless `-SkipConsent`).
- Creates a client secret and prints the values **once** on screen. **Nothing is written to disk.**
- Is safe to re-run: if an app with the same name exists it stops and tells you, instead of creating a duplicate (use `-DisplayName` for another name).

Run it in a normal PowerShell window (not in an embedded or headless terminal): the sign-in window needs a parent window.

---

## 2. Mailbox prerequisites

- The sender address used by a device must be an **existing mailbox** in your tenant (user mailbox or **shared mailbox**). Graph cannot send as an address that is not a mailbox.
- A **shared mailbox needs no licence** (up to 50 GB) and is the usual choice for "printer@contoso.com". It does not need sign-in enabled, because the relay never signs in as that mailbox.
- SMTP AUTH on the mailbox is **not** required: the relay does not use Microsoft's SMTP endpoint.
- Messages sent through Graph are stored in the sender mailbox's **Sent Items** by default. Large volumes in a small mailbox can fill it; set a retention policy if needed.
- Make sure SPF/DKIM/DMARC for your domain are in place as for any other outgoing mail from Microsoft 365.

---

## 3. Recommended: limit which mailboxes the app can send as

Out of the box, `Mail.Send` (application) lets the app send as **every** mailbox. If the relay or its secret is compromised, an attacker could send as anyone in your organisation. To limit this, use **Exchange Online RBAC for Applications** and scope the app to specific mailboxes.

> Microsoft's older *Application Access Policies* (`New-ApplicationAccessPolicy`) are being replaced by RBAC for Applications. Use RBAC for Applications for new setups.

Run in Exchange Online PowerShell (`Connect-ExchangeOnline`), with your own values:

```powershell
$appId  = '<application (client) ID>'
$spId   = '<object ID of the ENTERPRISE APPLICATION (service principal), not the app registration>'

# 1. Register the service principal in Exchange Online
New-ServicePrincipal -AppId $appId -ObjectId $spId -DisplayName 'office-smtprelay'

# 2. Define which mailboxes are allowed. Example: a mail-enabled security group "smtp-relay-senders"
#    that contains the sender mailboxes (e.g. printer@contoso.com)
$group = Get-DistributionGroup 'smtp-relay-senders'
New-ManagementScope -Name 'SmtpRelaySenders' `
  -RecipientRestrictionFilter "MemberOfGroup -eq '$($group.DistinguishedName)'"

# 3. Allow the app to send mail, only for that scope
New-ManagementRoleAssignment -App $spId -Role 'Application Mail.Send' -CustomResourceScope 'SmtpRelaySenders'

# 4. Verify
Test-ServicePrincipalAuthorization -Identity $spId -Resource printer@contoso.com   # InScope = True
Test-ServicePrincipalAuthorization -Identity $spId -Resource someone-else@contoso.com   # InScope = False
```

Then **remove the tenant-wide Graph consent** so that only the scoped Exchange assignment applies: in the Entra admin center open **Enterprise applications** -> `office-smtprelay` -> **Permissions** and revoke the tenant-wide `Mail.Send` grant (or, if you created the app with the helper script, run it with `-SkipConsent` next time). Wait a while for role changes to propagate (can take up to about 30 minutes), then re-run the two `Test-ServicePrincipalAuthorization` checks.

You can find the service principal object ID under **Enterprise applications** -> `office-smtprelay` -> **Overview** -> **Object ID**.

If you accept that the relay can send as any mailbox (small tenants, trusted network), you can skip this section.

---

## 4. Secret lifetime and rotation

Client secrets expire (maximum 24 months). When the secret expires, **all mail through the relay stops**.

- Note the expiry date when you create the secret. The relay UI will warn you before it expires.
- To rotate: create a **second** secret in **Certificates & secrets**, enter it in the relay's *Microsoft connection* page, test, then delete the old secret.
- Store the secret only on the host running the relay (see `.env.example` once available). Never commit it or paste it into chat, tickets or documents.

---

## 5. Troubleshooting

| Symptom (relay log) | Likely cause |
|---|---|
| `401` / `invalid_client` | Wrong or expired client secret, or the *Secret ID* was used instead of the *Value*. |
| `AADSTS700016` | Wrong client (application) ID or wrong tenant ID. |
| `403 Forbidden` / `ErrorAccessDenied` | Admin consent missing, the sender mailbox is outside the RBAC scope, or role changes are still propagating. |
| `404` / `MailboxNotEnabledForRESTAPI` | The sender address is not a (cloud) mailbox in this tenant. |
| `429` | Throttling; the relay retries with back-off. |
| Mail accepted but lands in spam | Check SPF/DKIM/DMARC for your domain. |
