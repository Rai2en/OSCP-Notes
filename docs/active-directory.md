# Active Directory: from credentials to a verified path

[Home](../README.md) · [AD commands](../README.md#active-directory-pentesting) · [Pivoting](pivoting.md)

## 1. Establish identity and transport

Record the domain DNS name, DC IP/FQDN, current user, local versus domain context, reachable hosts and the route used. Resolve the DC before debugging Kerberos. Verify clock alignment; an authentication error may be transport, DNS or time-related.

Kali example with synthetic lab values:

```bash
export DC_IP=192.0.2.20
export DOMAIN=lab.example
export AD_USER=student
read -rsp 'Lab password: ' AD_PASS; echo
dig @"$DC_IP" "_ldap._tcp.dc._msdcs.$DOMAIN" SRV
nxc smb "$DC_IP" -d "$DOMAIN" -u "$AD_USER" -p "$AD_PASS"
nxc smb "$DC_IP" -d "$DOMAIN" -u "$AD_USER" -p "$AD_PASS" --shares
```

The variable avoids putting a literal password in the command history, but command-line arguments can still be visible to local processes. Keep secrets in your private notebook. Test the known pair on one host before expanding to a documented target list. A successful SMB login does not grant administrative or WinRM access. [NetExec authentication reference](https://www.netexec.wiki/smb-protocol/authentication/checking-credentials-domain).

## 2. Collect and verify the graph

Use a collector compatible with your BloodHound deployment. The repository's older Neo4j/PowerShell examples are legacy notes. For CE, follow [SpecterOps collection guidance](https://bloodhound.specterops.io/collect-data/ce-collection/overview); [BloodHound.py](https://github.com/dirkjanm/BloodHound.py) documents its CE and legacy variants.

```bash
# Kali: only if the CE-compatible bloodhound-ce-python entry point is installed.
mkdir -p bloodhound
cd bloodhound
bloodhound-ce-python -d "$DOMAIN" -u "$AD_USER" -p "$AD_PASS" -ns "$DC_IP" -c All --zip
```

Check collection errors, domain identity and missing hosts before trusting an empty graph. Mark only identities you actually control. For each path, write the source principal, target object, edge/permission and supporting evidence. Verify important permissions against the live directory; a collected graph can be incomplete or stale.

## 3. Interpret permissions before changing anything

| Finding | Verify first | Decision |
|---|---|---|
| GenericAll on a group | Effective right, exact group, inheritance | Membership control may create a useful path |
| GenericAll/ForceChangePassword on a user | Object type and effective right | Password change has consequences; record the modification |
| GenericWrite / WriteDACL / WriteOwner | Allowed attributes, ACL and object type | These are different capabilities, not interchangeable labels |
| Group membership or session edge | Current membership/session and target reachability | Check whether it actually enables the next access method |
| Replication rights | Required rights and scope | DCSync requires appropriate directory permissions |
| Delegation or certificate configuration | Exact configuration and prerequisites | Treat as a separate verified technique, not an automatic shortcut |

Consult the upstream [GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all) and [ForceChangePassword](https://bloodhound.specterops.io/resources/edges/force-change-password) explanations for object-specific behavior. Do not assume an edge named AllExtendedRights always means every useful operation on every object type.

## 4. Track credentials and authentication types

For every discovery, note origin, principal, domain/local scope, secret type and verified services in [the credential inventory](../templates/credentials.md).

- AS-REP roasting and Kerberoasting have different account prerequisites; use their distinct [reference sections](../README.md#as-rep-roasting).
- An NT hash, Net-NTLMv2 challenge-response and Kerberos ticket are not interchangeable.
- Cached domain credentials are not automatically reusable as NT hashes.
- Local SAM data is not a dump of the domain database. Record where a hash came from before inferring cross-host access.
- For reuse tests, record the actual username/password pair; avoid accidentally testing every combination of two lists. Check lockout policy before any spraying.

## 5. Move, then re-enumerate

Select SMB/WMI/WinRM/RDP according to reachability and permissions. On each new host, confirm identity, groups, hostname, interfaces, local services and scoped secrets. Revisit the graph with newly verified information. Preserve enough evidence to explain each transition without relying on screenshots alone.

Record the final path in [the machine template](../templates/machine.md). Keep temporary credential variables only for the remaining credential-dependent steps and manage logs privately.

## 6. AD CS and current hardening

For Certipy 5, confirm `certipy find -h`; Kali may expose the launcher as `certipy-ad`. Enumerate first, using your private session variables:

```bash
certipy find -u "$AD_USER@$DOMAIN" -p "$AD_PASS" -dc-ip "$DC_IP" -enabled -text
```

Read the complete CA/template results, not only a vulnerability label. Enrollment permissions, client-authentication EKUs, subject control, approval/signature requirements and identity mapping determine whether a path is usable. The [upstream usage guide](https://github.com/ly4k/Certipy/wiki/05-%E2%80%90-Usage) and [command reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference) document version-specific options and ESC paths.

On updated DCs, strong certificate mapping changes invalidate older UPN-only assumptions; compatibility-mode support ended with the September 2025 updates. Validate SID/mapping behavior and DC patch level rather than assuming an issued certificate authenticates as the requested user. See [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Shadow Credentials requires effective access to the target's `msDS-KeyCredentialLink` and a compatible authentication environment. It is not the same prerequisite as enrolling in a template. For relay, check destination signing and EPA/channel binding. These paths are documented through [upstream Certipy](https://github.com/ly4k/Certipy); no new PoC is included here.

See [chain compatibility](command-audit.md#recheck-every-transition-in-a-chain) for ticket, DCSync and DCOM limitations. Run `unset AD_PASS` after the final credential-dependent command; this does not erase secrets already captured in logs.
