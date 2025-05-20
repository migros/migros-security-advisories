# Migros Security Advisory
This is a security advisory published by the Security Operations / Cyber Defense Center team of MGB (Migros-Genossenschafts-Bund) found during penetration tests or red team engagements.

## Odoo 15 (and possibly earlier) - Authenticated account takeover
| Key | Value |
| --- | --- |
| Vendor | Odoo |
| Product | Odoo |
| Vulnerability | Read access to OAuth access tokens and resulting account takeover |
| Affected Versions | 15 |
| URL | [https://www.odoo.com/](https://www.odoo.com/) |
| CVSS 4.0 | 8.7 |
| CWE | CWE-200 |
| CAPEC | CAPEC-87, CAPEC-233 |
| MSEC ID | MSEC-2025-002 |
| Vendor ID | ODOO-SA-2024-12-23 |
| CVE ID | CVE-2024-12368 |

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
Improper access control in the auth_oauth module of Odoo Community 15.0 and Odoo Enterprise 15.0 allows an internal user to export the OAuth tokens of other users.
Non-privileged users can access other users' OAuth access tokens in Odoo 15 (and possibly earlier) by using the Export feature of Odoo. They can then use these looted OAuth access tokens to log into the user accounts that the token belongs to. This vulnerability allows for horizontal and vertical privilege escalation.


## 2. Details
- "Log in with a regular user account (regular meaning: no global admin privileges, i.e. neither Administration=Access rights or Administration=Settings under the 'Administration' section in the user configuration)"
- "Either guess the correct action ID for the User model list view or, if known, directly browse to it. A valid URL looks, for example, like this: https://67085569-15-0-all.runbot183.odoo.com/web#cids=1&menu_id=4&action=72&model=res.users&view_type=list"
- Select all users with the check boxes
- Click on Action > Export
- Select the OAuth access token field to be included in the export
- Download the export
- Open the export file to receive the OAuth access tokens
- Use the stolen tokens to log in using the OAuth endpoint at /auth_oauth/signin


## 3. Workaround and Fix
The following chapter describes how the reported vulnerability can be mitigated (e.g., using a workaround) and if available sustainably fixed.
### Workaround
Disable OAuth login for your Odoo installation and/or all users


### Fix
- Do not allow the OAuth Implicit Flow for login. Use something that is more secure.
- Protect the OAuth Access Token field in all affected versions against being read, also during Export.
- Consider not storing the OAuth Access Token at all after successful authentication, if possible.



## 6. Credits
- Rafael Fedler, Migros-Genossenschafts-Bund (MGB)

## 7. Timeline
| Date | Process | Comments |
| --- | --- | --- |
| 16.08.2024 | Vulnerability Discovery | None |
| 20.08.2024 | Vendor Notification | None |
| 20.08.2024 | Vendor Receipt | None |
| 20.08.2024 | Vendor Validation | None |
| 20.08.2024 | Vendor Resolution | Vendor creates patch in GitHub code base as pull request 177259. |
| 23.12.2024 | Vendor Resolution | Security advisory (ODOO-SA-2024-12-23) published by vendor to subscribers. |
| 15.01.2025 | Vendor Resolution | Security advisory published by vendor to public through GitHub as issue 193854. |
| 25.02.2025 | Vendor Resolution | CVE published as CVE-2024-12368. |
| 20.05.2025 | Advisory Release | This advisory (MSEC-2025-002) published by Migros-Genossenschafts-Bund (MGB). |

## 8. References
- [https://www.odoo.com/](https://www.odoo.com/)
- [https://github.com/migros/security-advisories](https://github.com/migros/security-advisories)

## 9. About Us
The MGB (Migros-Genossenschafts-Bund) is the central service company of the Migros Group and offers around 350 different functions. For this reason, we are always on the lookout for specialists from a wide range of fields. You can find us on [jobs.migros.ch](https://migros-gruppe.jobs/de/unsere-unternehmen/migros-gruppe/offene-stellen?q=cyber).


## 10. Disclaimer
The MGB (Migros-Genossenschafts-Bund) works with suppliers to mitigate identified vulnerabilities as best as possible. The publication of vulnerabilities without the availability of a suitable corrective measure (patch) is not the goal of the MGB. The full disclosure of a vulnerability is only used by MGB in exceptional cases. The protection of the Migros community, especially those who are in a contractual relationship, must be guaranteed in any case and MGB will act in their interests.


