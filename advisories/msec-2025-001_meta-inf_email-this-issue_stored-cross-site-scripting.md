# Migros Security Advisory
This is a security advisory published by the Security Operations / Cyber Defense Center team of MGB (Migros-Genossenschafts-Bund) found during penetration tests or red team engagements.

## META-INF - Email This Issue - Stored Cross-Site Scripting
| Key | Value |
| --- | --- |
| Vendor | META-INF |
| Product | Email This Issue |
| Vulnerability | Stored Cross-Site Scripting |
| Affected Versions | 9.12.0-GA |
| URL | [https://www.meta-inf.hu/en/apps/email-this-issue-for-jira](https://www.meta-inf.hu/en/apps/email-this-issue-for-jira) |
| CVSS 4.0 | 8.6 |
| CWE | CWE-79 |
| CAPEC | CAPEC-63, CAPEC-592 |
| MSEC ID | MSEC-2025-001 |
| Vendor ID | n/a |
| CVE ID | CVE-2024-42912 |

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
Special characters are not properly sanitized or output-encoded by Email This Issue prior to rendering within Jira's web UI, allowing for stored cross-site scripting.


## 2. Details
An e-mail address is made up of a local part and a domain part. According to `RFC 5233`, special characters are also allowed in the local part. When rendering e-mails and their related metadata (like e-mail addresses, date sent, subject, etc.) in a rich context (e.g., a website), it is important that potential special characters are neutralized in a suitable fashion through escaping or output-encoding appropriate for the target context (e.g., HTML). A stored cross-site scripting vulnerability was found in the Jira App "Email This Issue" by META-INF as it fails to neutralize special characters in e-mail addresses. Fields containing e-mail addresses are not processed through escaping or encoding and can thus contain HTML or script content, which then gets rendered by user agents (browsers) when displaying e-mails consumed by the Email This Issue Jira plug-in.

The local part is not validated properly and is interpreted as HTML or script code by the application.

Steps to reproduce:

1. Create a folder (e.g., `Import-Inbox`) inside a mailbox.
2. Add an `Incoming Mail Configuration`, connect it with the mailbox and specify the folder `Import-Inbox`.
3. Configure a mail handler which updates an existing or creates an new issue.
4. Place an e-mail with the manipulated (payload) recipients address in the `Import-Inbox` folder of the mail account that is watched by the app.
   * Example payload: `"xss-test.<script>alert('XSS-Test')</script>"@domain.tld`
5. Wait until the email has been imported.
6. Open the email tab in the corresponding issue.
7. `XSS-Test` shows up.
8. In the email tab you see the imported email an the corresponding HTML.


## 3. Workaround and Fix
The following chapter describes how the reported vulnerability can be mitigated (e.g., using a workaround) and if available sustainably fixed.
### Workaround
Disable incoming mail handlers.


### Fix
It must be ensured that all data rendered within a web context are properly neutralized for the target context, usually through escaping or output-encoding suitable for the target context.
Version `9.13.0-GA` of Email This Issue fixes the mentioned stored cross-site vulnerability.



## 4. Credits
- Antonio Kulhanek, MGB (Migros-Genossenschafts-Bund)
- Damiano Esposito, MGB (Migros-Genossenschafts-Bund)

## 5. Timeline
| Date | Process | Comments |
| --- | --- | --- |
| 17.06.2024 | Vulnerability Discovery | n/a |
| 20.06.2024 | Vendor Notification | First submission. |
| 22.06.2024 | Vendor Receipt | Not reproducible. |
| 23.06.2024 | Vendor Notification | Second submission. |
| 24.06.2024 | Vendor Receipt | n/a |
| 24.06.2024 | Vendor Validation | n/a |
| 23.07.2024 | Vendor Resolution | n/a |
| 01.08.2024 | CVE-ID Request | n/a |
| 20.05.2025 | Advisory Release | n/a |

## 6. References
- [https://github.com/migros/migros-security-advisories/blob/main/advisories/msec-2025-001_meta-inf_email-this-issue_stored-cross-site-scripting.md](https://github.com/migros/migros-security-advisories/blob/main/advisories/msec-2025-001_meta-inf_email-this-issue_stored-cross-site-scripting.md)
- [https://github.com/migros/migros-security-advisories/](https://github.com/migros/migros-security-advisories/)
- [https://datatracker.ietf.org/doc/html/rfc5233](https://datatracker.ietf.org/doc/html/rfc5233)
- [https://modzero.com/en/blog/beyond_the_at_symbol/](https://modzero.com/en/blog/beyond_the_at_symbol/)
- [https://marketplace.atlassian.com/apps/4977/email-this-issue?hosting=datacenter&tab=versions](https://marketplace.atlassian.com/apps/4977/email-this-issue?hosting=datacenter&tab=versions)
- [https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

## 7. About Us
The MGB (Migros-Genossenschafts-Bund) is the central service company of the Migros Group and offers around 350 different functions. For this reason, we are always on the lookout for specialists from a wide range of fields. You can find us on [jobs.migros.ch](https://migros-gruppe.jobs/de/unsere-unternehmen/migros-gruppe/offene-stellen?q=cyber).


## 8. Disclaimer
The MGB (Migros-Genossenschafts-Bund) works with suppliers to mitigate identified vulnerabilities as best as possible. The publication of vulnerabilities without the availability of a suitable corrective measure (patch) is not the goal of the MGB. The full disclosure of a vulnerability is only used by MGB in exceptional cases. The protection of the Migros community, especially those who are in a contractual relationship, must be guaranteed in any case and MGB will act in their interests.


