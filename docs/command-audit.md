# Command compatibility review

[Home](../README.md) · [AD workflow](active-directory.md) · [External CVEs](cve-references.md)

Reviewed **2026-09-10**, from baseline `6ba3826`. Sources and argument definitions were checked; offensive commands were not run against targets. An upstream option can differ from an older installed package. Record `--help`/version output before using a workflow.

## Corrections and version boundaries

| Area | Current guidance | Primary reference |
|---|---|---|
| FreeRDP | Check whether your package provides `xfreerdp3` or `xfreerdp`. Clipboard flags are unrelated to login failures. | [Kali package/help](https://www.kali.org/tools/freerdp3/) |
| WPScan | Use `--output` and `--format`; removed obsolete redirect/log switches. API token is needed for vulnerability database detail. | [Kali package/help](https://www.kali.org/tools/wpscan/) |
| Impacket remote execution | `smbexec` opens a semi-interactive shell and has no trailing command argument. `psexec`, `wmiexec` and `atexec` have different prerequisites and arguments. | [smbexec parser](https://github.com/fortra/impacket/blob/master/examples/smbexec.py) |
| NetExec credential lists | `--no-bruteforce` pairs corresponding rows. Without it, lists test combinations. `--continue-on-success` controls stopping, not pairing or lockout protection. | [CLI definitions](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/cli.py) |
| Hash formats | Impacket uses `LM:NT` (empty LM allowed); hashcat modes depend on the exact hash prefix/type. Removed blanket `--force`. | [Impacket](https://github.com/fortra/impacket), [Hashcat formats](https://hashcat.net/wiki/doku.php?id=example_hashes) |
| BloodHound | CE needs compatible collectors; legacy desktop/Neo4j instructions do not install CE. | [Collectors](https://bloodhound.specterops.io/collect-data/ce-collection/overview), [Python variants](https://github.com/dirkjanm/BloodHound.py) |
| Windows enumeration | Prefer CIM to WMIC. Service-control ACL, binary ACL and restart ability are separate checks. | [Service rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) |
| Impersonation tools | SeImpersonate is a prerequisite, not proof of compatibility. PrintSpoofer is archived; inspect OS, service and runtime requirements for each implementation. | [PrintSpoofer](https://github.com/itm4n/PrintSpoofer), [JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG) |
| Linux enumeration | Corrected PTY quoting, process flags and executable-file search. Sudo rules are user/run-as/argument specific. | [GNU find](https://www.gnu.org/software/findutils/manual/html_mono/find.html), [sudo manual](https://www.sudo.ws/docs/man/sudo.man/) |
| NFS | `showmount` does not reveal root-squash options; server configuration and the target's execution mount matter. | [exports](https://man7.org/linux/man-pages/man5/exports.5.html), [showmount](https://man7.org/linux/man-pages/man8/showmount.8.html) |
| SMB transfer | Guest access and signing policies may prevent older anonymous transfer examples. | [Microsoft SMB hardening](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening) |

## Recheck every transition in a chain

| Proposed transition | Required evidence / current limitation |
|---|---|
| Web flaw → shell | Confirm execution under the application identity and a reachable callback path; file read/upload alone is insufficient. |
| Service write access → SYSTEM | Identify privileged service identity, correct executed path, effective write/configuration rights and an available trigger. |
| New local administrator → remote session | Account scope, RDP/WinRM authorization, firewall and remote token policy still apply. |
| SMB authentication → relay | Target protocol protections, signing, channel binding/EPA and usable authentication must all be assessed. Signing changes in newer Windows make legacy assumptions unreliable. |
| Certificate → domain authentication | Check template rights, EKU, issuance conditions, identity/SID mapping and KDC support. A returned PFX is not proof of successful impersonation. |
| Service key → silver ticket | SPN, key type and service behavior matter; PAC signature enforcement can invalidate older forged-ticket recipes. |
| krbtgt key → golden ticket | Domain identity, existing principal, key material, supported encryption and current PAC handling matter; patch levels must be recorded. |
| Local admin → DCSync | Local administrative rights on a member server do not grant domain replication rights. DCSync reads via replication, not by copying NTDS.dit. |
| DCOM access → execution | RPC reachability, activation rights, registered application and authentication-level hardening all matter. |

Hardening references: [certificate mapping KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers), [PAC signatures KB5020805](https://support.microsoft.com/en-US/servicing/os/windows-server/2022/10/kb5020805-how-to-manage-kerberos-protocol-changes-related-to-cve-2022-37967), [DCOM KB5004442](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c).

## Limits of this review

This corrects identified syntax and prerequisite errors; it does not certify every historical payload or third-party binary in the README. Machine-specific DeadPotato instructions, a truncated DCOM payload and blanket kernel-exploit success claims were removed. Existing attributed payload examples were not expanded. New CVE material is external links only.

The notebook scripts are offline and unchanged. Local link checks and the helper tests validate repository mechanics, not exploit success. No PoC was created, installed or executed during this review.
