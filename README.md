# VulDB Reports

Vulnerability reports for open-source PHP projects, reproduced locally (phpStudy, 127.0.0.1 only) and submitted to VulDB.

## Index

| # | Product | Report | VulDB |
|---|---------|--------|-------|
| 1 | SourceCodester Drug Recommendation System 1.0 — Blind SQL injection in `/Admin/add_user.php` (`txtpassword`, unauthenticated) | [drug-recommender/01-SQL注入.md](drug-recommender/01-SQL%E6%B3%A8%E5%85%A5.md) | pending |
| 2 | SourceCodester Drug Recommendation System 1.0 — Stored XSS via `/patient.php` `txtname` → `/Admin/recommend.php` | [drug-recommender/02-XSS.md](drug-recommender/02-XSS.md) | pending |
| 3 | SourceCodester Secured E-Voting System 1.0 - Unrestricted File Upload to RCE (unauthenticated) via /voter_signup.php (user_image) | [e-voting/01-任意文件上传RCE-未认证.md](https://github.com/qwer1230011107/vuldb-reports/blob/main/e-voting/01-%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0RCE-%E6%9C%AA%E8%AE%A4%E8%AF%81.md) | pending |
| 4 | SourceCodester Secured E-Voting System 1.0 - Unrestricted File Upload to RCE (authenticated) via /candidate_signup.php (candidate_photo) | [e-voting/02-任意文件上传RCE-登录用户.md](https://github.com/qwer1230011107/vuldb-reports/blob/main/e-voting/02-%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0RCE-%E7%99%BB%E5%BD%95%E7%94%A8%E6%88%B7.md) | pending |
| 5 | SourceCodester Secured E-Voting System 1.0 - Missing RBAC across /Admin/ - voter self-promotion to eleco via /Admin/edit_voter.php (role, is_verified) | [e-voting/03-后台越权自提权.md](https://github.com/qwer1230011107/vuldb-reports/blob/main/e-voting/03-%E5%90%8E%E5%8F%B0%E8%B6%8A%E6%9D%83%E8%87%AA%E6%8F%90%E6%9D%83.md) | pending |
| 6 | SourceCodester Secured E-Voting System 1.0 - OTP brute force - no rate limit on /otp_verify.php (code), 90k space cracked in 67s | [e-voting/04-OTP爆破.md](https://github.com/qwer1230011107/vuldb-reports/blob/main/e-voting/04-OTP%E7%88%86%E7%A0%B4.md) | pending |
| 7 | SourceCodester Secured E-Voting System 1.0 - Hard-coded Gmail SMTP credentials in /login.php | [e-voting/05-硬编码SMTP凭据.md](https://github.com/qwer1230011107/vuldb-reports/blob/main/e-voting/05-%E7%A1%AC%E7%BC%96%E7%A0%81SMTP%E5%87%AD%E6%8D%AE.md) | pending |
| 8 | SourceCodester Secured E-Voting System 1.0 - Hard-coded AES ballot key (ccc@@) - offline ballot decryption in /election/ballot.php | [e-voting/06-选票加密密钥硬编码.md](https://github.com/qwer1230011107/vuldb-reports/blob/main/e-voting/06-%E9%80%89%E7%A5%A8%E5%8A%A0%E5%AF%86%E5%AF%86%E9%92%A5%E7%A1%AC%E7%BC%96%E7%A0%81.md) | pending |
| 9 | SourceCodester Secured E-Voting System 1.0 - Missing CSRF on vote casting - /election/ballot.php (votes[], cast_vote) | [e-voting/07-投票无CSRF.md](https://github.com/qwer1230011107/vuldb-reports/blob/main/e-voting/07-%E6%8A%95%E7%A5%A8%E6%97%A0CSRF.md) | pending |
| 10 | SourceCodester Secured E-Voting System 1.0 - No candidate validation on voting - pending candidates receive counted votes | [e-voting/08-投票校验缺失.md](https://github.com/qwer1230011107/vuldb-reports/blob/main/e-voting/08-%E6%8A%95%E7%A5%A8%E6%A0%A1%E9%AA%8C%E7%BC%BA%E5%A4%B1.md) | pending |
| 11 | SourceCodester Secured E-Voting System 1.0 - Reflected XSS in /election/ballot.php (id) | [e-voting/09-反射XSS.md](https://github.com/qwer1230011107/vuldb-reports/blob/main/e-voting/09-%E5%8F%8D%E5%B0%84XSS.md) | pending |

| 12 | SourceCodester Barangay Resident Profiling and Information Management System 1.0 - Arbitrary file deletion via /users.php (current_image, ../ traversal unlink) | [brpms/01-任意文件删除.md](brpms/01-%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E5%88%A0%E9%99%A4.md) | pending |
| 13 | SourceCodester Barangay Resident Profiling and Information Management System 1.0 - Reflected XSS via /manage_members.php (household_id) | [brpms/02-反射XSS.md](brpms/02-%E5%8F%8D%E5%B0%84XSS.md) | pending |
| 14 | SourceCodester Barangay Resident Profiling and Information Management System 1.0 - Stored XSS via /households.php (purok) rendered raw in /reports.php | [brpms/03-存储XSS-purok.md](brpms/03-%E5%AD%98%E5%82%A8XSS-purok.md) | pending |
| 15 | SourceCodester Barangay Resident Profiling and Information Management System 1.0 - Stored XSS via resident last_name rendered raw in /residents.php | [brpms/04-存储XSS-居民姓名.md](brpms/04-%E5%AD%98%E5%82%A8XSS-%E5%B1%85%E6%B0%91%E5%A7%93%E5%90%8D.md) | pending |
| 16 | SourceCodester Barangay Resident Profiling and Information Management System 1.0 - Stored XSS via occupation rendered raw in /reports.php | [brpms/05-存储XSS-occupation.md](brpms/05-%E5%AD%98%E5%82%A8XSS-occupation.md) | pending |
