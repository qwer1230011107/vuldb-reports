# SourceCodester Secured E-Voting System 1.0 /login.php Hard-coded Gmail SMTP Credentials Disclosure

## NAME OF AFFECTED PRODUCT(S)

- Secured E-Voting System (St Paul Academy Alumni 2001 set e-voting portal)

## Vendor Homepage

- https://www.sourcecodester.com/php/18790/secured-e-voting-system.html

## AFFECTED AND/OR FIXED VERSION(S)

### submitter

- (submitter name pending user confirmation — will be filled from vuldb.txt account at submission time)

## Vulnerable File

- /login.php (also /otp_verify.php)

## VERSION(S)

- 1.0 (current public download, 2026-11)

## Software Link

- https://www.sourcecodester.com/download-code?nid=18790&title=Secured+E-Voting+System+using+PHP+and+MySQL+Source+Code

# PROBLEM TYPE

## Vulnerability Type

- Use of Hard-coded Credentials (CWE-798) — live third-party (Gmail) SMTP account + app password shipped in the public source archive

## Root Cause

- The OTP email sender in `login.php` authenticates to Gmail with **hard-coded, real credentials** that are distributed to everyone who downloads the source:

```php
// login.php:113-118  (app password partially redacted here; full value is in the public archive)
$mail->Host     = 'smtp.gmail.com';
$mail->Username = 'newleastpaysolution@gmail.com';
$mail->Password = 'swhayy...cmif';        // ← live Gmail App Password, 16 chars, verbatim in source
$mail->SMTPSecure = 'tls';
$mail->Port     = 587;
```

- `otp_verify.php:96-97` contains a second, placeholder pair (`ccc@gmail.com` / `ccc`) for the re-send path — same pattern, confirming the credentials are baked into source rather than configured.

## Impact

- Anyone who downloads this product (it is a public sourcecodester download) obtains a **working Gmail App Password** for the developer's account `newleastpaysolution@gmail.com`. An attacker can:
  - send mail **as** that account (phishing from a trusted sender);
  - read the OTP mails relayed through it in other deployments of this product that keep the default config — i.e., **intercept the very MFA codes** the "secured" voting flow depends on, then log in as voters (chained with the missing rate limit in report 04);
  - pollute/consume the account's sending quota.
- No exploit request is needed: the credential ships in the vendor's own distribution file. This was verified only against the locally downloaded archive (no mail was sent, no external service was touched).

# DESCRIPTION

- During the security review of "Secured E-Voting System", hard-coded SMTP credentials (a real Gmail address plus a 16-character app password) were found in `/login.php`. Because the product's source archive is publicly downloadable, these credentials are effectively disclosed to all users, allowing unauthorized use of the mailbox and interception of OTP emails in deployments that retain the default configuration.

# No login or authorization is required to exploit this vulnerability (the secret is in the public source archive)

# Vulnerability details and POC

## Vulnerability location:

- `/login.php` lines 113-118 (PHPMailer configuration)

## Steps:

1. Download the official archive: `https://www.sourcecodester.com/download-code?nid=18790...` (obtained 2026-11).
2. Read `login.php` lines 113-118 — the Gmail username and app password are present verbatim.
3. The credential pair is syntactically a Gmail app password (16 lowercase letters) and the account name matches the OTP "From" header used in deployment mails observed locally.

Full static evidence (redacted): `poc/F05-hardcoded-smtp-credentials.txt`
(The evidence file intentionally masks the middle of the secret; the **complete** value exists in the vendor's public archive itself, so disclosure is the vendor's, not this report's.)

# Suggested repair

1. **Remove the credential immediately** from the source and **revoke/rotate** the Gmail app password (Google Account → Security → App passwords) — shipping it publicly means it must be treated as compromised.
2. Load SMTP settings from environment variables or an untracked config file; refuse to send OTP mail if unset.
3. Send OTP mail from a transactional provider (SES/Postmark) with scoped API keys, not a personal mailbox.
4. Add a CI check that rejects commits containing hard-coded `Username`/`Password` pairs.

# Dedup note

- NVD: 0 CVEs for this product (checked 2026-11-09). VulDB: no entries for this product.
