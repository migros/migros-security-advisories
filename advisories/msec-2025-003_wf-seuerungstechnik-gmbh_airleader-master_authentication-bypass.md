# Migros Security Advisory
This is a security advisory published by the Security Operations / Cyber Defense Center team of MGB (Migros-Genossenschafts-Bund) found during penetration tests or red team engagements.

## WF Steuerungstechnik GmbH - airleader MASTER - Authentication Bypass
| Key | Value |
| --- | --- |
| Vendor | WF Steuerungstechnik GmbH |
| Product | airleader MASTER |
| Vulnerability | Authentication Bypass |
| Affected Versions | 3.00571 |
| URL | [https://www.airleader.de/produkte/steuerungen/](https://www.airleader.de/produkte/steuerungen/) |
| CVSS 4.0 | 10.0 |
| CWE | CWE-287 |
| CAPEC | CAPEC-115 |
| MSEC ID | MSEC-2025-003 |
| Vendor ID | n/a |
| CVE ID | Pending |

## Table of Contents
1. Summary
2. Details
3. Workaround and Fix
4. Credits
5. Timeline
6. References
7. About Us
8. Disclaimer

## 1. Summary
Airleader MASTER is a control system for compressors. Access to the web interface is protected with a password. The vulnerability allows bypassing the login.


## 2. Details
Further information will follow (see Migros vulnerability disclosure process).

The authentication (i.e., the login form) can easily be bypassed by entering a less than (`<`) sign.


## 3. Workaround and Fix
The following chapter describes how the reported vulnerability can be mitigated (e.g., using a workaround) and if available sustainably fixed.
### Workaround
n/a


### Fix
Version number `3.00572` fixes the authentication bypass vulnerability.



## 4. Credits
- Antonio Kulhanek, MGB (Migros-Genossenschafts-Bund)
- Damiano Esposito, MGB (Migros-Genossenschafts-Bund)

## 5. Timeline
| Date | Process | Comments |
| --- | --- | --- |
| 20.04.2023 | Vulnerability Discovery | n/a |
| 20.04.2023 | Vendor Notification | n/a |
| 20.04.2023 | Vendor Receipt | n/a |
| 20.04.2023 | Vendor Validation | n/a |
| 21.04.2023 | Vendor Resolution | n/a |
| 04.06.2025 | CVE Request | n/a |
| 04.06.2025 | Advisory Release | n/a |

## 6. References
- [https://github.com/migros/migros-security-advisories/](https://github.com/migros/migros-security-advisories/)
- [https://www.airleader.de/produkte/steuerungen/](https://www.airleader.de/produkte/steuerungen/)
- [https://github.com/migros/security-advisories](https://github.com/migros/security-advisories)

## 7. About Us
The MGB (Migros-Genossenschafts-Bund) is the central service company of the Migros Group and offers around 350 different functions. For this reason, we are always on the lookout for specialists from a wide range of fields. You can find us on [jobs.migros.ch](https://migros-gruppe.jobs/de/unsere-unternehmen/migros-gruppe/offene-stellen?q=cyber).


## 8. Disclaimer
The MGB (Migros-Genossenschafts-Bund) works with suppliers to mitigate identified vulnerabilities as best as possible. The publication of vulnerabilities without the availability of a suitable corrective measure (patch) is not the goal of the MGB. The full disclosure of a vulnerability is only used by MGB in exceptional cases. The protection of the Migros community, especially those who are in a contractual relationship, must be guaranteed in any case and MGB will act in their interests.


