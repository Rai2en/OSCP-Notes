# Privilege escalation: prove the prerequisite

[Home](../README.md) · [Windows commands](../README.md#windows-privilege-escalation) · [Linux commands](../README.md#linux-privilege-escalation)

An enumeration tool suggests candidates. Validate the relevant identity, permission, trigger and resulting execution context before treating a candidate as a path.

## Linux triage

```bash
id
hostname
uname -a
sudo -l
ss -lntup
find / -type f -perm -4000 2>/dev/null
getcap -r / 2>/dev/null
```

| Candidate | Evidence required | Common wrong inference |
|---|---|---|
| sudo entry | Exact allowed command, arguments and run-as identity | A listed command always gives a shell |
| SUID/capability | Owner, effective permission and program behavior | Any SUID binary is vulnerable |
| Cron/timer | Privileged trigger plus writable executed component | Writable unrelated file is sufficient |
| PATH hijack | Unqualified executable lookup in a privileged process | Changing your own PATH changes every service |
| Local service | Binding address, version, identity and access | A remote scan sees loopback services |
| Config/history secret | Read access, principal and successful validation | A database password must be the root OS password |
| Kernel exploit | Exact build/configuration and advisory prerequisites | Kernel version alone proves applicability |

For a candidate binary, compare its documented behavior with a matching [GTFOBins entry](https://gtfobins.github.io/), then verify the actual permission context. Prefer targeted configuration and permission checks before broad filesystem searches or unstable kernel techniques.

## Windows triage

PowerShell:

```powershell
whoami /all
hostname
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,OSArchitecture
Get-CimInstance Win32_Service | Select-Object Name,StartName,State,PathName
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
```

Use `sc.exe` explicitly in PowerShell: `sc` can resolve to an alias. For an identified service:

```powershell
sc.exe qc <SERVICE_NAME>
sc.exe sdshow <SERVICE_NAME>
icacls '<FULL_PATH_TO_SERVICE_BINARY>'
icacls '<PARENT_DIRECTORY>'
```

| Candidate | Evidence required | Common wrong inference |
|---|---|---|
| Service binary replacement | Writable binary/directory, higher service identity, trigger | Being able to read the binary permits replacing it |
| Unquoted service path | Ambiguous path containing spaces, writable candidate location, trigger | Missing quotes alone are sufficient |
| Service configuration | Permission to change configuration, not just file ACLs | File permissions equal service-control permissions |
| Scheduled task | Task identity, action, writable component and execution time | Every task runs elevated |
| Token impersonation | Privilege, OS/tool compatibility and required service | SeImpersonate guarantees every Potato variant works |
| Backup/registry access | Effective read/export rights and source hive/database | Local SAM equals domain credentials |
| AlwaysInstallElevated | Relevant user and machine policy configuration | One registry value proves the complete path |
| Saved credentials | Origin, scope and usable authentication method | A saved secret always grants local admin |

Record the smallest reversible change needed in an authorized lab and how to restore it. After the attempt, prove the actual resulting identity and privileges. A file created with `touch` is a marker, not an executable shell; a tool printing “success” is not evidence of the required privilege level.

References: [Windows service security](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), [icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls), [PEASS](https://github.com/peass-ng/PEASS-ng).
