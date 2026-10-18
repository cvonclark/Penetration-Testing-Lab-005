# Project 005 — SMB Share Permission Assessment

**Environment:** Isolated VMware host-only lab | Windows Server 2025 domain controller `DC01` (`corp.lab`, `192.168.42.10`) | Kali Linux | Standard domain test account `CORP\jcarter`  
**Assessment status:** Initial access demonstrated; share-level remediation retested; folder and existing-file ACL cleanup verified locally.  
**Scope:** Owned, deliberately misconfigured lab systems and fictional data only.

## Executive summary

I assessed an intentionally misconfigured Windows SMB share named `Finance`. The share granted `CORP\Domain Users` **Change** access, while the underlying NTFS directory granted the group **Modify**. Using the low-privilege account `CORP\jcarter`, I enumerated the share, listed its contents, downloaded and read a fictional budget file, and uploaded a new test file. These observations demonstrated excessive access under the lab's administrator-only Finance access policy.

I removed broad SMB and NTFS permissions, retested from Kali, and observed `NT_STATUS_ACCESS_DENIED` for directory listing, file download, and file upload. I then removed inherited `BUILTIN\Users` permissions from the folder and cleaned up an existing test file's `CORP\jcarter` Full Control entry. The final file ACL was verified with `icacls`; **a fresh Kali retest after the last file-level ACL cleanup was not performed**.

## Objective and threat model

Determine whether an ordinary domain user can access restricted Finance files over SMB; demonstrate the impact using fictional files; apply least-privilege remediation; and verify access is blocked. The intentional vulnerability was created solely for this lab.

## Tools

- **PowerShell** — create the test directory and SMB share; inspect and modify share access.
- **`icacls`** — inspect, modify, and verify NTFS permissions.
- **`smbclient` on Kali Linux** — enumerate shares, connect as a standard domain user, download files, and upload a harmless test file.

## Lab setup and vulnerable configuration

Windows Server PowerShell (administrative context):

```powershell
New-Item -Path 'C:\LabShares\Finance' -ItemType Directory -Force
Set-Content -Path 'C:\LabShares\Finance\budget-demo.txt' -Value 'LAB DATA ONLY - Fictional Finance Budget'
New-SmbShare -Name 'Finance' -Path 'C:\LabShares\Finance' -FullAccess 'Administrators' -ChangeAccess 'Domain Users'
Get-SmbShareAccess -Name 'Finance'
icacls 'C:\LabShares\Finance' /grant 'CORP\Domain Users:(OI)(CI)M'
icacls 'C:\LabShares\Finance'
```

The initial share ACL showed `BUILTIN\Administrators: Full` and `CORP\Domain Users: Change`. The initial NTFS ACL showed additional inherited `BUILTIN\Users` permissions. The explicit `Domain Users: Modify` NTFS grant was deliberately added to test unauthorized write access.

## Assessment and verified results

Kali commands (authenticated using the lab account; passwords are not included):

```bash
smbclient -L //192.168.42.10 -U 'CORP\jcarter'
smbclient //192.168.42.10/Finance -U 'CORP\jcarter'
```

Inside the interactive SMB client:

```text
ls
get budget-demo.txt
put smb-write-test.txt
ls
```

A local test file was prepared using `echo 'LAB TEST - Unauthorized write access' > smb-write-test.txt`. The screenshot evidence shows successful directory listing, retrieval of `budget-demo.txt`, and successful upload of `smb-write-test.txt` (37 bytes). **No overwrite of an existing file, deletion, credential theft, or domain compromise was demonstrated.**

| Tested behavior | Before remediation | After share-level remediation |
|---|---|---|
| List `Finance` directory | Allowed | `NT_STATUS_ACCESS_DENIED` |
| Download `budget-demo.txt` | Allowed; fictional contents verified | `NT_STATUS_ACCESS_DENIED` |
| Upload a new test file | Allowed | `NT_STATUS_ACCESS_DENIED` |

**Troubleshooting note:** After remediation, one `smbclient` invocation displayed an interactive `smb: \>` prompt. That alone did not prove file access. An actual `ls` request was denied, as were subsequent download and upload requests. An earlier attempt had also produced `tree connect failed: NT_STATUS_ACCESS_DENIED`. Report the tested file operations, not an assumption based on the prompt.

## Finding: Excessive SMB and NTFS permissions

**Classification:** Broken access control / overly permissive file-share authorization.  
**Affected asset:** `\\192.168.42.10\Finance` (`C:\LabShares\Finance`).  
**Affected identity:** `CORP\jcarter` (member of `Domain Users` and `IT-Staff` in the checked AD group-membership output).  
**Severity:** **High (illustrative lab assessment, not a formal CVSS score)**, assuming restricted Finance files of business significance.  
**Impact:** Unauthorized reading of restricted data and creation of files; potential confidentiality and integrity risk. The assessment did not demonstrate modification of an existing file.

**Root cause:** Share-level Change permission and NTFS Modify permission were granted too broadly to `CORP\Domain Users`. Inherited `BUILTIN\Users` entries and a surviving file-level `jcarter` Full Control entry required additional hardening.

## Remediation and verification

Share permission remediation:

```powershell
Revoke-SmbShareAccess -Name 'Finance' -AccountName 'CORP\Domain Users' -Force
Get-SmbShareAccess -Name 'Finance'
```

The resulting share ACL listed only `BUILTIN\Administrators: Full`. After this change, the low-privilege account's **listing, download, and upload operations were denied** in the screenshots.

Folder NTFS cleanup:

```powershell
icacls 'C:\LabShares\Finance' /remove:g 'CORP\Domain Users'
icacls 'C:\LabShares\Finance' /inheritance:d
icacls 'C:\LabShares\Finance' /remove:g 'BUILTIN\Users'
icacls 'C:\LabShares\Finance'
```

`/inheritance:d` copied inherited ACL entries to explicit entries, enabling removal of the unwanted `BUILTIN\Users` entries. The final folder ACL showed administrator, SYSTEM, and CREATOR OWNER entries; broad Users/Domain Users entries were absent.

File-level cleanup (the uploaded test file retained `CORP\jcarter: Full Control` during review):

```powershell
icacls 'C:\LabShares\Finance\smb-write-test.txt' /inheritance:d
icacls 'C:\LabShares\Finance\smb-write-test.txt' /remove:g 'CORP\jcarter'
icacls 'C:\LabShares\Finance\smb-write-test.txt'
```

The final file ACL listed only SYSTEM and Administrators with Full Control. `budget-demo.txt` was also inspected and showed only SYSTEM and Administrators Full Control. **The screenshot-based post-remediation SMB retests preceded the final file-level cleanup.**

## Evidence index

Screenshots are in [`screenshots/`](screenshots/). Selected evidence:

| Evidence | Demonstrates |
|---|---|
| `02-SMB-Share-Permissions.png` | Broad Domain Users share-level Change access |
| `04-Vulnerable-NTFS-Permissions.png` | Broad Domain Users NTFS Modify access |
| `07-Unauthorized-File-Read.png` | Download and read of fictional Finance file |
| `08-Unauthorized-SMB-Write.png` | New file uploaded as low-privilege user |
| `09-SMB-Share-Remediation.png` | Domain Users removed from share ACL |
| `14-Post-Remediation-Listing-Denied.png` | Directory listing denied |
| `15-Post-Remediation-Download-Denied.png` | Download denied |
| `16-Post-Remediation-Upload-Denied.png` | Upload denied |
| `19-Folder-NTFS-Hardened.png` | Folder ACL after removing broad Users access |
| `20-File-ACL-Review.png` | Discovery of residual user-specific file access |
| `21-File-ACL-Cleanup.png` | Residual user-specific file permission removed |

## Lessons learned

- **Share and NTFS ACLs are distinct:** check both when assessing network file access.
- **A successful connection prompt is not proof of authorization:** test actual operations and record the server response.
- **Permission inheritance matters:** parent-folder changes do not necessarily eliminate file-specific access already present.
- **Verify remediation with the original account:** repeat the same operations that previously succeeded.

**Safety note:** This project was performed on a host-only lab using fictional data. Do not reproduce these permissions on production resources.
