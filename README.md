# Mediroza General Hospital

## Security Assessment Engagement

### Milestone 1 - Application Mapping & Surface Discovery

**Assessment Type:** Black-Box Penetration Test

**Target:** https://medirozahospital.com

**Phase:** Application Mapping & Exposed Entry Points

**Analyst:** Anderson Edaiyo Uzezi

**Assessment Date:** 22 November 2026

---

# Executive Summary

The objective of this phase was to map the externally exposed attack surface of the target application and identify all entry points where user input is accepted or sensitive functionality is exposed.

This phase was non-intrusive. No exploitation payloads were sent. Mapping was performed to prioritize targets for controlled testing in the next phase.

---

# Assessment Scope

| Item | Value |
|--------|--------|
| Target Domain | medirozahospital.com |
| Target IP | 199.188.201.16 |
| Assessment Type | Black-Box |
| Phase | Application Mapping |
| Status | Complete |

---

# Tools Utilized

| Tool | Purpose |
|--------|--------|
| Curl | Header and file discovery (robots.txt, sitemap.xml) |
| WhatWeb | Technology fingerprinting and form discovery |
| Gobuster | Directory and file enumeration |
| Browser (Manual) | Manual application crawling and input mapping |


---

# Baseline Intelligence (From Reconnaissance)

| Finding | Value |
|--------|--------|
| Web Server | LiteSpeed |
| Protocol | HTTP/2 + HTTPS Enforced |
| WAF | LiteSpeed Web Application Firewall Detected |
| Registrar | NameCheap |
| Mail Security | SPF + DMARC Present |
| Public IP | 199.188.201.16 |

**Analyst Note:** The presence of a LiteSpeed WAF indicates that aggressive scanning will be blocked. Enumeration was therefore conducted at low thread count with a common wordlist to avoid triggering defensive controls.

---
### 1.1 `robots.txt`

#### Command 1
```bash
curl -I https://medirozahospital.com/robots.txt
```

#### Finding
```http
HTTP/2 200
content-type: text/plain
last-modified: Fri, 04 Sep 2026 02:03:53 GMT
accept-ranges: bytes
content-length: 132
date: Wed, 25 Nov 2026 01:51:05 GMT
server: LiteSpeed
x-turbo-charged-by: LiteSpeed
```
* **Evidence:** `SS007-ROBOTS.png` - Screenshot 1

#### Command 2
```bash
curl -s https://medirozahospital.com/robots.txt
```

#### Finding
```text
User-agent: *
Disallow: /patient/
Disallow: /staff/
Disallow: /old/

Sitemap: https://medirozahospital.com/sitemap.xml
```

* **Evidence:** `SS007-ROBOTS.png` - Screenshot 2

#### Analyst Notes
* The first command confirms `robots.txt` exists and is publicly accessible with `HTTP 200` (a 132-byte plain-text file served by LiteSpeed).
* The second command shows the file discloses three restricted paths (`/patient/`, `/staff/`, and `/old/`), two of which (`/patient/` and `/staff/`) correspond to portals referenced in the public site navigation, while `/old/` is entirely unlinked. 
* All three paths were added to the priority testing list. Exposing unlinked directories like `/old/` constitutes **Information Disclosure**, allowing an attacker to identify restricted or legacy areas without brute-forcing.
* It also confirms the sitemap location at `/sitemap.xml`, used in the next step.

---

### 1.2 `sitemap.xml`

#### Command 1
```bash
curl -s https://medirozahospital.com/sitemap.xml
```

#### Finding
```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://medirozahospital.com/index.html</loc></url>
  <url><loc>https://medirozahospital.com/about.html</loc></url>
  <url><loc>https://medirozahospital.com/doctors.html</loc></url>
  <url><loc>https://medirozahospital.com/contact.html</loc></url>
</urlset>
```

* **Evidence:** `SS008-SITEMAP.png` - Screenshot 1

#### Command 2
```bash
curl -s https://medirozahospital.com/sitemap_index.xml
```

#### Finding
```html
404 Not Found
<title>404 Not Found</title>
<h1>404</h1>
<h2>Not Found</h2>
<p>The resource requested could not be found on this server!</p>
Proudly powered by LiteSpeed Web Server
```
* **Evidence:** `SS008-SITEMAP.png` - Screenshot 2

#### Analyst Notes
* The first command shows `sitemap.xml` lists only 4 public pages: `index.html`, `about.html`, `doctors.html`, and `contact.html`. It does **not** list login, appointment, search, or admin pages.
* The second command confirms `sitemap_index.xml` does not exist (`404 Not Found`), meaning there is only a single sitemap file rather than an index of multiple sitemaps.
* The public attack surface exposed via the sitemap is therefore limited to those 4 pages.

---

### 1.3 `security.txt`

#### Command
```bash
curl -I https://medirozahospital.com/.well-known/security.txt
```

#### Finding
```http
HTTP/2 404
date: Wed, 25 Nov 2026 02:20:04 GMT
server: LiteSpeed
x-turbo-charged-by: LiteSpeed
```
* **Status:** Not Present
* **Evidence:** `SS009-SECURITYTXT.png`

#### Analyst Notes
* The request returns `HTTP 404 Not Found`, confirming `security.txt` is **Not Present**.
* No vulnerability disclosure contact, security policy, or reporting email is published at `/.well-known/security.txt`.
* Because there is no defined channel for security researchers to report vulnerabilities to the site owner, this is logged as a **Low / Informational** best-practice finding.


### 2. Application Crawling (Manual)

All public pages were manually visited to identify user-controllable inputs.

#### Discovered Pages

| # | Page | URL | Purpose |
| :--- | :--- | :--- | :--- |
| 1 | Homepage | `/index.html` | Public landing |
| 2 | About | `/about.html` | Public info |
| 3 | Doctors | `/doctors.html` | Public info |
| 4 | Contact | `/contact.html` | User Input Form |
| 5 | Patient Portal Login | `/patient/login.php` | Authentication |
| 6 | Staff Login | `/staff/login.php` | Authentication |
| 7 | Old Directory | `/old/` | Directory Listing - Exposed Backup |

* **Evidence:** `SS010-SITE-MAP.png`
* **Note:** No `/login`, `/search?q=`, `/appointment`, `/upload`, or `/admin` page was found. Those template entries were removed as they were not confirmed.

---

### 3. Exposed Entry Points Register

This is the core deliverable of this phase. Every place the application accepts input is an entry point.

| ID | Entry Point | Type | URL / Location | Input Fields / Parameters | Risk Priority |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **E-001** | Patient Login Form | Form (`POST`) | `/patient/login.php` | `patient ID`, `password` | **HIGH** - Auth Handling |
| **E-002** | Staff Login Form | Form (`POST`) | `/staff/login.php` | `staff ID`, `password` | **HIGH** - Auth Handling |
| **E-003** | Contact Form | Form (`POST`) | `/contact.html` | `name`, `email`, `message` | **Medium** |
| **E-004** | Old Directory Listing | Directory Listing | `/old/` | No input - exposes `mediroza_db_backup_2019.sql` | **CRITICAL** - Data Exposure |
| **E-005** | `robots.txt` / `sitemap.xml` | Information Disclosure | `/robots.txt`, `/sitemap.xml` | No input | **Low** - Info Disclosure |

* **Evidence:** `SS011-ENTRY-POINTS.png`

#### Analyst Assessment
The Login / Authentication forms at `/patient/login.php` and `/staff/login.php` were identified as the highest-value entry points. The assignment hint for Milestone 1 states:
> *"Analyse the behaviour of any authentication mechanisms you find"* and *"Gain unauthorised access to a restricted area."*

Therefore, **E-001** and **E-002** were prioritized for controlled authentication testing in the next phase. **E-004** was prioritized as a **Critical** finding for immediate remediation — no patient data was downloaded. Other entry points (**E-003**, **E-005**) were noted for secondary testing.

---

### 4. Directory & File Enumeration

#### Command
```bash
gobuster dir -u https://medirozahospital.com -w /usr/share/wordlists/dirb/common.txt -t 10 --no-error -o gobuster.txt
```

#### Findings

| Path Found | Status Code | Significance |
| :--- | :--- | :--- |
| `/robots.txt` | `200` (132 bytes) | Discloses `/patient/`, `/staff/`, `/old/` |
| `/sitemap.xml` | `200` (391 bytes) | Lists only 4 public pages |
| `/wp-admin` | `200` (745 bytes) | **FALSE POSITIVE** - Cloudflare JS challenge, not WordPress |
| `/old/` | `200` | **Directory Listing ENABLED** - exposes `mediroza_db_backup_2019.sql` |
| `/admin`, `/amanda`, etc. | `301` | **FALSE POSITIVES** - Server redirects all `/~*` |
| `/.htaccess`, `/.git/HEAD` | `403` | Blocked - Positive control |
| `/admin`, `/login`, `/uploads`, `/backup` | Not Found | Not confirmed - No reliable `200` response |

* **Evidence:** `SS012-GOBUSTER.png`

#### Analyst Notes
* Enumeration was conducted at a low thread count (`10`) due to the detected LiteSpeed WAF.
* Gobuster results were deemed **INCONCLUSIVE** due to Cloudflare Bot Protection / WAF intervention. A request to `/wp-admin` via `curl` returned `HTTP 200` with a 745-byte page (`<title>Checking your browser</title>`).
* Repeated `403` responses indicated WAF intervention, which was recorded as a positive defensive control, and scanning was paused. Manual browser-based enumeration was used as the authoritative method.

---

## 4. Technology Correlation

### Tool Used

```bash
whatweb -v https://medirozahospital.com
```

### Findings

#### Web Server
* **Server:** LiteSpeed Server
* **Header:** `x-turbo-charged-by: LiteSpeed`
* **Powered By:** LiteSpeed

#### Application Framework
No CMS or framework was positively identified. The application is believed to be custom-built in PHP based on:
* `.php` login endpoints (`/patient/login.php`, `/staff/login.php`)
* Static `.html` content
* Absence of CMS fingerprints
* No generator tags observed

#### Identified Forms

| Method | Endpoint | Purpose |
| :--- | :--- | :--- |
| `POST` | `/patient/login.php` | Patient Login |
| `POST` | `/staff/login.php` | Staff Login |
| `POST` | `/contact.html` | Contact Form |

* **Evidence:** `SS013-WHATWEB-FORMS.png`

---

## Attack Surface Summary

| Category | Count |
| :--- | :--- |
| **Total Pages Mapped** | 7 |
| **Total Entry Points** | 5 |
| **High Priority Entry Points** | 3 |
| **Admin / Restricted Paths Identified** | 3 |
| **File Upload Locations** | 0 |
| **GET Parameters Observed** | 0 |

### Confidence Rating

| Activity | Confidence |
| :--- | :--- |
| **Manual Enumeration** | High |
| **Automated Enumeration** | Low |

#### Breakdown
* **4** pages identified from `sitemap.xml`
* **2** authentication portals
* **1** exposed directory listing
* **High-priority targets:** `E-001` (Patient Login), `E-002` (Staff Login), `E-004` (Exposed Backup Directory)
* No upload functionality or `GET` parameters were observed during testing.

---

## Key Findings

### Finding F-01: Authentication Entry Points Identified

* **Severity:** `HIGH`
* **Status:** Selected for testing during the next assessment phase

#### Description
Two authentication systems were identified:
* Patient Portal Authentication
* Staff Portal Authentication

These portals represent the primary security boundary of the application and therefore constitute the highest-value targets for further assessment.

#### Affected Endpoints
* `/patient/login.php`
* `/staff/login.php`

---

## Finding F-02: Publicly Accessible Database Backup via Directory Listing

* **Severity:** `CRITICAL`
* **Status:** Confirmed — Immediate Remediation Required
* **Affected Endpoint:** `https://medirozahospital.com/old/mediroza_db_backup_2019.sql`

---

### Description

During application mapping and attack surface discovery, a critical information exposure was identified involving a publicly accessible database backup file.

The exposure originated from an entry in the application's `robots.txt` file (`https://medirozahospital.com/robots.txt`):

```text
Disallow: /old/
```

Although intended to prevent search engine crawlers from indexing the path, this directive disclosed a legacy directory not linked in the public navigation. Navigating directly to `https://medirozahospital.com/old/` returned an open directory listing (`Index of /old/`) instead of an access control response (`403 Forbidden` or `404 Not Found`), exposing `mediroza_db_backup_2019.sql` without authentication.

---

### Discovery Path

```text
robots.txt
    │
    ▼
Disallow: /old/
    │
    ▼
Manual Request to /old/
    │
    ▼
Directory Listing Enabled (Index of /old/)
    │
    ▼
mediroza_db_backup_2019.sql Exposed
    │
    ▼
Backup File Retrieved Without Authentication
```

---

### Evidence

| Evidence ID | Description |
| :--- | :--- |
| `SS007-ROBOTS.png` | `robots.txt` disclosure of `/old/` |
| `SS010-SITE-MAP.png` | Application mapping overview |
| `SS011-ENTRY-POINTS.png` | Entry point inventory |
| `SS012-GOBUSTER.png` | Directory enumeration validation |
| `OLD PAGE.png` | Open directory listing exposure (`Index of /old/`) |

---

### Verification

The open directory listing at `https://medirozahospital.com/old/` exposed the following file metadata:
* **Filename:** `mediroza_db_backup_2019.sql`
* **Last Modified:** `2026-09-04 02:02`
* **Size:** `7 KB`
* **Server Banner:** `LiteSpeed Web Server at medirozahospital.com Port 443`

A direct `GET` request to `https://medirozahospital.com/old/mediroza_db_backup_2019.sql` successfully returned the SQL dump (`-- Generated by Mediroza CMS 1.4.2 backup module`, Database: `mediroza_hr`) without requiring:
* Authentication or credentials
* Authorization or role checks
* Active session validation

---

### Root Cause Analysis

The exposure resulted from four compounding security misconfigurations:

1. **Information Disclosure via `robots.txt`:** Publishing `Disallow: /old/` advertised an unlinked legacy directory to anyone inspecting the file.
2. **Directory Listing Enabled:** Auto-indexing was active on `/old/`, allowing unauthenticated visitors to enumerate the directory contents.
3. **Sensitive Backup Stored in Web Root:** A database dump (`mediroza_db_backup_2019.sql`) was left inside a publicly served web directory.
4. **Missing Access Controls:** No server-level authentication or IP restrictions prevented unauthenticated downloads of `.sql` files.

---

### Security Impact

The exposed SQL backup completely bypassed the application's authentication boundaries (the Patient and Staff portals), enabling an unauthenticated attacker to extract internal records directly from the web server.

Inspection of the database header and schema confirms exposure of the `mediroza_hr` database, impacting:
* **Personally Identifiable Information (PII):** Full names, personal email addresses, phone numbers, and national ID numbers for 30 hospital staff members (table `staff`).
* **Financial & HR Records:** Staff job titles, departments, hire dates, and monthly salaries in ZAR (`monthly_salary_zar`).
* **Corporate Ownership Data:** Shareholder names, share classes, share counts, and ownership percentages (table `shareholders`).
* **Application Fingerprinting:** Database schema structure and internal CMS version (`Mediroza CMS 1.4.2`), aiding further targeted attacks.

---

### Analyst Assessment

This finding represents the most severe vulnerability discovered during the Application Mapping phase. It required no brute-forcing, exploit payloads, or aggressive scanning—only passive inspection of `robots.txt` followed by a direct browser request.

Because the SQL dump was retrievable without authentication and contains sensitive HR, PII, and corporate ownership records, it was immediately classified as **Critical** and escalated for containment and full impact analysis.

---

### Remediation

1. **Immediate Removal:** Delete `mediroza_db_backup_2019.sql` and any other legacy files from `/old/` and all publicly accessible web directories immediately.
2. **Disable Directory Indexing:** Disable auto-indexing globally on the LiteSpeed web server (e.g., `Options -Indexes` in `.htaccess` or via the LiteSpeed WebAdmin Console).
3. **Relocate Backups:** Move all database backups to a secure, encrypted storage location outside the public web root.
4. **Enforce Access Controls:** Block direct HTTP access to sensitive file extensions (`.sql`, `.bak`, `.tar.gz`, `.zip`) at the web server / WAF level.
5. **Log Audit & Breach Assessment:** Review historical web server access logs for `/old/` to determine whether unauthorized parties previously downloaded the file, and initiate internal breach/compliance notification procedures (e.g., POPIA) regarding the exposed staff PII.

---

### Risk Rating

| Metric | Rating |
| :--- | :--- |
| **Likelihood** | High |
| **Impact** | Critical |
| **Overall Risk** | **CRITICAL** |



## Conclusion

Application mapping objectives were successfully completed, resulting in a comprehensive inventory of exposed functionality, publicly accessible resources, authentication entry points, and potential attack surfaces.

Manual and automated reconnaissance activities successfully identified two primary authentication portals, multiple user-controlled entry points, and a critical data exposure issue involving a publicly accessible database backup file.

During assessment activities, information disclosed through `robots.txt` led to the discovery of a legacy directory (`/old/`) containing an open directory listing. Further validation confirmed that the database dump at `/old/mediroza_db_backup_2019.sql` was publicly accessible and could be retrieved without authentication.

The exposed backup file represents the most significant finding identified during the Application Mapping phase and was immediately escalated for further investigation during subsequent assessment milestones.

Automated enumeration results were partially impacted by Cloudflare and LiteSpeed protections; therefore, manual verification was used as the authoritative source for all confirmed findings. Sufficient intelligence has now been gathered to support authentication testing, access control assessment, and detailed analysis of the exposed backup file during the next phases of the engagement.

### Checklist Summary

* ✅ 7 pages mapped
* ✅ 5 entry points identified
* ✅ Authentication mechanisms identified
* ✅ Attack surface documented
* ✅ Critical exposed backup file identified
* ✅ Public directory listing confirmed
* ✅ Database backup file accessibility verified
* ✅ WAF protections observed
* ✅ Manual verification completed
* ✅ High-priority assessment targets established

---

## Next Phase: Milestone 1 – Initial Access & Authentication Testing

Assessment will proceed using controlled and authorized testing procedures in accordance with the approved Rules of Engagement.

### Primary Assessment Targets

1. **Authentication Mechanism Testing**
   * Patient Login Portal (`/patient/login.php`)
   * Staff Login Portal (`/staff/login.php`)
2. **Critical Exposure Review**
   * Publicly exposed database backup (`/old/mediroza_db_backup_2019.sql`)

### Milestone 1 Objectives

* Analyze authentication behavior and session handling
* Evaluate access control mechanisms across restricted paths
* Obtain access to restricted functionality where authorized
* Validate the scope of data exposure from the publicly accessible backup file
* Identify any additional sensitive resources exposed through the application

---

> **Assessment Status:** ✅ Application Mapping Complete  
> **Outcome:** Attack Surface Successfully Mapped  
> **Critical Finding Identified:** Public Database Backup Exposure (`/old/mediroza_db_backup_2019.sql`)  
> **Next Phase:** Milestone 1 – Initial Access & Authentication Testing


## 👤 Author
**Anderson Edaiyo Uzezi**  
Cybersecurity Professional B084  
LinkedIn: https://www.linkedin.com/in/anderson-edaiyo-bab74117b
