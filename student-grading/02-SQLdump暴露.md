# SourceCodester Student Grading System with Report Card and GWA 1.0 /database.sql Sensitive Data Exposure (Unauthenticated SQL Dump Download)

## Author

- (submitter name pending user confirmation — will be filled from vuldb.txt account at submission time)

## Vendor and Software Links

- https://www.sourcecodester.com/php/18870/student-grading-system-report-card-and-gwa-using-php-and-mysql-source-code.html
- https://www.sourcecodester.com/download-code?nid=18870

## Overview

- Student Grading System with Report Card and GWA (Using PHP and MySQL), version 1.0 (current public download, 2026-11), ships its full database dump `database.sql` inside the web root. On the documented deployment paths — copying the project folder into XAMPP's `htdocs` (README.txt:14) or serving it with any static-capable PHP setup — the file is exposed to the internet as a plain download. Anyone without an account can retrieve the complete schema, the bcrypt password hashes of every account (administrator and teachers), and personal data of all students (student numbers, full names, courses, year levels). The hashes correspond to publicly documented default passwords, so the dump hands an attacker both the accounts and the keys.

## Details

- Vulnerable file: `/database.sql` (shipped in the web root; nothing removes or protects it)
- Affected version: 1.0 (current public download, 2026-11)
- The product's own installation instructions leave the dump in place:

```
-- database.sql:2
-- Import this file in phpMyAdmin or run: mysql -u root -p < database.sql
```

```
README.txt:13-17
HOW TO RUN (XAMPP)
1. Copy the "student-grading-system" folder into C:\xampp\htdocs\
2. Start Apache and MySQL in the XAMPP Control Panel.
3. Open http://localhost/phpmyadmin, click Import, choose database.sql and click Go.
```

- The dump contains, among other content, the account table with its known bcrypt hashes and the student PII:

```sql
-- database.sql:66-69
INSERT INTO users (id, username, password_hash, full_name, role) VALUES
(1,'admin','$2y$10$hZPiqmUdKLKpJ1Q0U3kssuTOQFV7zgr61gBPtChe3VXdyymaGyKV2','System Administrator','admin'),
(2,'mreyes','$2y$10$woW9jEa3Xn6u26HbVDS8O.J6n0QEwgQqumhr1oJ8xUR2nkX.9.uAa','Maria Reyes','teacher'),
(3,'jdelacruz','$2y$10$woW9jEa3Xn6u26HbVDS8O.J6n0QEwgQqumhr1oJ8xUR2nkX.9.uAa','Jose Dela Cruz','teacher');
```

```sql
-- database.sql:71-83 (12 students in total)
INSERT INTO students (id, student_no, first_name, last_name, course, year_level) VALUES
(1,'2026-0001','Ana','Cruz','BSIT',1),
...
```

- No `.htaccess`, no PHP front-controller, and no access check protects the file: the application is a set of flat PHP scripts, and the served deployment answers requests for `/database.sql` with the raw file (`Content-Type: application/x-sql`), before and independently of any authentication logic.

## Description

- Any visitor can download the application's entire database definition from the web root without an account. The download reveals: the full schema of `users`, `students`, `subjects`, `classes`, `enrollments`; the bcrypt hashes of the administrator and teacher passwords (which correspond to the default passwords published on the login page — offline cracking is a formality); and personal data of all students (student numbers, full names, course, year level). Combined with the default-credentials finding, the dump gives an attacker complete pre-authenticated knowledge of the deployment: accounts, hash formats, table layout, and every identifier needed for targeted attacks. On a production deployment with real student records, the same channel exposes the live data if operators follow the product's habit of keeping database artifacts in the project folder.

## PoC

- Unauthenticated single-request download of the dump (verified over HTTP, local deployment):

```
GET /database.sql HTTP/1.1
Host: 127.0.0.1:8147
```

- Response (verbatim, headers plus first lines of the body):

```
HTTP/1.1 200 OK
Host: 127.0.0.1:8147
Content-type: application/x-sql

-- Student Grading System (PHP + MySQL)
-- Import this file in phpMyAdmin or run: mysql -u root -p < database.sql

CREATE DATABASE IF NOT EXISTS student_grading CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE student_grading;

DROP TABLE IF EXISTS enrollments;
DROP TABLE IF EXISTS classes;
DROP TABLE IF EXISTS subjects;
DROP TABLE IF EXISTS students;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
...
```

- The 4,622-byte body contains the complete dump, including the `users` INSERT with the three bcrypt hashes and all 12 student PII rows. The same unauthenticated request to `/README.txt` (HTTP 200) additionally discloses the default-accounts section.

## Payload

```
GET /database.sql   -> full schema + bcrypt password hashes + student PII (no session required)
GET /README.txt     -> default account documentation (no session required)
```

## Evidence

- This finding is verified entirely over HTTP; the complete request/response exchanges (headers, content type, hash/PII presence checks) are preserved in `poc/C2-sql-exposure.txt`. No web-page screenshot is required — the leaked file itself is the vulnerability's direct output (browsers treat `application/x-sql` as a download).

## Suggested repair

1. **Keep database artifacts out of the web root:** ship `database.sql` and `README.txt` outside the served directory (e.g. a `dist/` folder excluded from the zip's docroot layout, or a separate download package).
2. **Block direct access as defense in depth:** add an `.htaccess` rule (Apache) or a front-controller deny-list for `*.sql`/`*.md`/`*.txt` so a dump left behind is not served.
3. **Purge PII/hashes from the shipped dump:** distribute a schema-only dump plus a minimal demo dataset with fake names and no real account hashes.
4. **Rotate seeds on install:** an install wizard should create the administrator account at setup time and delete demo accounts rather than importing fixed rows.

## Dedup note

- NVD: keyword search "Student Grading System" returns 20 CVEs (checked 2026-11-10) — all target homonymous products and all are SQL injection or XSS; no entry covers SQL-dump/web-root exposure for any of them.
- VulDB: no entry for this product. Site search was blocked by Cloudflare, so three independent search-engine index passes restricted to vuldb.com were used (product name / author / nid / "database.sql" variants) — no entry for this product and no database.sql-exposure entry in the homonymous family (checked 2026-11-10).
