| # | Check | Tool/Command/Script | Module/Script Details | Inputs Needed | CVE | Expected Positive Result |
|:--|:---|:---|:---|:---|:---|:---|
| 1 | Ex-User Credential Validation | SAP GUI | Manual login attempt | SAP IP, Client ID, Username, Password | None | Successful login |
| 2 | Default SAP Users Active (SAP*, DDIC) | SAP GUI | Manual login attempt | SAP IP, Client ID, SAP*/DDIC with default password | None | Successful login |
| 3 | Password Hash Extraction | Metasploit | `auxiliary/admin/sap/sap_rfc_table_read` | RHOSTS, RPORT=3300, USERNAME, PASSWORD, CLIENT, TABLE=USR02 | None | Hashes dumped |
| 4 | RFC Command Execution (OS Command) | Metasploit | `auxiliary/admin/sap/sap_soap_rfc_exec` | RHOSTS, RPORT=8000, FUNCTION=SXPG_COMMAND_EXECUTE, CMD='whoami', USERNAME, PASSWORD | None | OS command executed |
| 5 | RFC ABAP Upload | Metasploit | `auxiliary/admin/sap/sap_soap_rfc_exec` | FUNCTION=RFC_ABAP_INSTALL_AND_RUN, Code input, USERNAME, PASSWORD | None | ABAP uploaded and executed |
| 6 | SAP Message Server Authentication Bypass | Metasploit | `auxiliary/admin/sap/sap_mgmt_con_bsx_auth_bypass` | RHOSTS, RPORT=3600 | CVE-2010-5326 | Message Server controlled |
| 7 | SAP Router Misconfiguration | Nmap | `sap-router-enum.nse` | IP of SAP Router, Port 3299 | None | Internal SAP systems exposed |
| 8 | SAP WebGUI Access (Web Pentest) | Burp Suite | Manual HTTP testing | URL: `http://<sap_ip>:8000/sap/bc/gui/sap/its/webgui` | None | Login page appears |
| 9 | SAP Public Web Directory Access | Browser / Burp Suite | Access `/sap/public/bc/` | URL: `http://<sap_ip>:8000/sap/public/bc/` | None | Public content visible |
| 10 | Weak Password Policy | SAP GUI | Transaction `RZ10` | Check `login/min_password_lng`, `login/password_expiration_time` | None | Weak values found |
| 11 | Transport Directory Write Access | SSH / Manual Access | Write to `/usr/sap/trans/` | OS access to transport directories | None | Upload possible |
| 12 | Dangerous TCODE Access (SE38, SM49) | SAP GUI | Transaction test | Try running SE38, SM49, SM69 | None | Able to execute OS commands |
| 13 | Session Hijack Risk | Wireshark | Capture SAP traffic | MITM unencrypted session | None | Credentials/sniffed data |
| 14 | SAP Web Dispatcher Directory Traversal | Burp Suite | Fuzz URL paths | `/sap/public/bc/icf_test.htm` traversal | None | Directory content exposed |
| 15 | SSO Ticket Forging | Manual | Check `login/accept_sso2_ticket` parameter | SAP GUI (RZ10) config | None | SSO forgery possible |
| 16 | Client Settings Weakness | SAP GUI | Transaction `SCC4` | Client modifiable flag | None | Full config tampering possible |
| 17 | RFC Gateway ACL Missing | Manual check or custom script | Check gw/acl_rules | SAP Kernel settings | None | Unrestricted program start |
| 18 | Open Management Ports (SAPMMC/SAPHostCtrl) | Nmap | Port scan (50013, 1128) | Target IP and ports | None | Admin control panel access |
| 19 | SAP Kernel Version Outdated | OS Command | `disp+work -version` | Shell access or SAP access | Multiple CVEs if old | Exploitable version found |
| 20 | SAP Web Info Leakage (HTTP Headers) | Burp Suite | Inspect HTTP headers | Via ICM/Web Dispatcher | None | SAP SID, instance, version leak |
| 21 | ABAP Debugger Abuse | SAP GUI | Debugging sessions | Enable debug during login | None | Code/data extraction |
| 22 | SAP Gateway Route Manipulation | Metasploit | `sap_soap_rfc_exec` | Malicious RFC_DEST creation | None | Pivot SAP routes |
| 23 | SAPHostControl RCE | Manual/Burp | Attack `/SMD/HOSTAGENT` endpoints | Port 1128, 1129 | CVE-2020-6287 (RECON) | Remote Code Execution |
| 24 | Logon Groups Information Leak | Metasploit | `auxiliary/scanner/sap/sap_mgmt_con_extract_logon_groups` | RHOSTS, RPORT=3600 | None | SID/Instance Information |
| 25 | Predictable Session IDs | Burp Suite + Fuzzing | Capture SAP Web sessions | Analyze SAP cookies | None | Session hijacking possible |
| 26 | Clipboard Leakage (saplogon.ini) | File Search | Check `%APPDATA%\SAP\Common\` | Local system access | None | IP, username found |
| 27 | SAP GUI Shortcut Injection | Manual | Create `.sap` file | Open shortcut file | None | Execute malicious transaction |
| 28 | SM37 Batch Job Injection | SAP GUI | Schedule jobs | SM37 transaction access | None | OS-level backdoor |
| 29 | Missing Security Audit Log | SAP GUI | Check `SM20` setup | No logging enabled | None | Stealth attack possible |
| 30 | RFC_READ_TABLE Unprotected | pyrfc script | Call RFC_READ_TABLE | Connection credentials | None | Any table data exposed |
| 31 | WebSocket SAP Service Testing | Burp / Browser | Fuzz WebSocket endpoints | SAP Web Dispatcher | None | Info leak / DOS possible |
| 32 | BAPI Misuse | pyrfc script | Abuse critical BAPIs | BAPI_USER_CHANGE / BAPI_COMPANYCODE_GETDETAIL | None | Data manipulation possible |
| 33 | RFC SMB Relay Attack | Custom Tool | Force SAP to connect SMB share | Capture NTLM hashes | None | Credential theft |
| 34 | Authorization Overprovisioning | SAP GUI | SUIM - Role search | User Authorization check | None | Privilege escalation |
| 35 | HTTP Request Smuggling (SAP ICM) | Burp Suite | Smuggle HTTP requests | Custom payloads | None | Response splitting |
| 36 | SAP HANA XS Engine Misconfiguration | Browser/Burp | Access `:80xx` ports | HANA XS default pages | None | DB access |
| 37 | SAP Portal Weakness | Manual/Burp | Check `/irj/portal` leaks | Public SAP Portal URLs | None | Info disclosure |
| 38 | Missing HTTPS on SAP ICM | Burp / Browser | Check if forced HTTPS | ICM configuration | None | Session hijack possible |
| 39 | SAP Router Admin Access | Manual/Telnet | Access SAPRouter control | SAPRouter open | None | Full SAP network access |
| 40 | ABAP Injection (Code) | SAP GUI | SE38, report modification | Upload backdoored ABAP | None | Remote code execution |
| 41 | Local Directory Traversal | Burp Fuzzing | Localhost SAP Web paths | `/sap/public/bc/` | None | Local file disclosure |
| 42 | SAP Gateway Program Launch | Metasploit | `sap_mgmt_con_bsx_auth_bypass` variant | RHOSTS, RPORT=3600 | None | Remote command execution |
| 43 | SAP Authorization Dump | pyrfc script | Extract all user roles | Table AGR_USERS | None | Reconnaissance |
| 44 | SAP Transport Submission Abuse | SAP GUI | Create fake Transport Request | Upload malicious code | None | Persistent RCE |
| 45 | Hardcoded SAP Credentials | Search binaries/scripts | Look inside SAP binaries | OS access | None | Password leaks |
| 46 | Poor Gateway Security Logging | Check Gateway logs | OS access required | Gateway no logging | None | Hidden attacks |
| 47 | Verbose SAP HTTP Errors | Burp | Trigger SAP errors | Look for system info leaks | None | Recon info gathered |
| 48 | SAP Host Agent Version Leak | Browser | Access `/SMD/HOSTAGENT/` | Hostagent info leaked | None | Pivot opportunities |
| 49 | Bypass SAP Firewall via SAPRouter | SAPRouter attack | Chain hops internally | Open router rules | None | Firewall bypass |
| 50 | SAP Early Watch Report Misuse | SAP GUI | Check transaction `ST03N` | System workload analysis | None | Resource enumeration |
