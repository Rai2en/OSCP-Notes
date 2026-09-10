# Start here

[Home](../README.md) · [Coverage and remaining work](coverage.md)

Use this repository to practice a repeatable workflow and retrieve commands quickly. Reading notes is not a substitute for solving unfamiliar labs and writing reproducible reports. Commands use synthetic examples; replace addresses and names with your authorized lab scope.

## Choose your situation

| Situation | Open this | Finish with |
|---|---|---|
| Preparing a Kali VM | [Toolkit](toolkit.md) | A tested VM snapshot and recorded tool versions |
| Starting a target | [Methodology](methodology.md) | Services, evidence, ranked hypotheses |
| Looking at a website | [Web workflow](web.md) | A confirmed behavior and repeatable request |
| Given domain credentials | [AD workflow](active-directory.md) | Identity, permissions and reachable hosts mapped |
| Internal host is unreachable | [Pivoting](pivoting.md) | A verified connection through a documented route |
| Have a shell, need higher privileges | [Privilege escalation](privilege-escalation.md) | Prerequisites checked and resulting identity proven |
| Tool or shell fails | [Troubleshooting](troubleshooting.md) | One tested explanation, not random retries |
| Preparing an exam attempt | [Exam checklist](exam.md) | Current rules read and reporting rehearsed |
| Planning practice | [Training](training.md) | Measurable skills and a review schedule |

## Start a private notebook

From the repository root:

```bash
python3 scripts/new_session.py ~/oscp-private/lab-01
```

This only creates local folders and Markdown templates. It makes no network requests, installs nothing, and refuses an existing destination. Keep the resulting directory outside a public repository.

## How to use a command

1. Identify where it runs: Kali Bash, target PowerShell, CMD, SQL, or a tool console.
2. State the prerequisite: reachable port, valid credential, writable file, particular permission, or compatible software version.
3. Save the command and relevant output. Explain what a positive result would mean.
4. After an error, check transport, authentication, authorization and compatibility separately.
5. After success, record identity, hostname, address and the next accessible resource.

The existing [command reference](../README.md#general) remains available. Its older examples are not all lab-validated. The new guides add decision criteria rather than promising that a named exploit works everywhere.

## Contribution standard

Use the [technique template](../templates/technique.md). Include prerequisites, expected evidence, failure cases, a primary source, and a validation status. See [contribution guidance](../CONTRIBUTING.md).
