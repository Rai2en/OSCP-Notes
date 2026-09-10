# Manual web workflow

[Home](../README.md) · [Existing web commands](../README.md#web-attacks)

Start with a saved request and a known baseline. Preserve method, path, Host header, cookies, content type and CSRF token. Change one input at a time. A generic HTTP 200 is not evidence of a vulnerability.

## Map the application

On Kali, use a lab URL, inspect redirects and source, and test a nonexistent path:

```bash
export URL=http://192.0.2.10:8080
curl -i "$URL/"
curl -i "$URL/robots.txt"
curl -i "$URL/this-path-should-not-exist-7f29"
```

Record virtual hosts, hidden fields, API endpoints, upload/download features, framework hints, source maps, configuration backups and authentication roles. Resolve a discovered hostname to the correct lab address; a redirect to a name is not a dead website. Calibrate directory discovery against the baseline before filtering response length/status.

## Match the test to the observation

| Observation | Minimal investigation | What does NOT prove success |
|---|---|---|
| File/path parameter | Read a known harmless local file; compare absolute/relative paths | An error page containing a guessed path |
| Local file inclusion | Establish that the file is interpreted/included, not just downloaded | Reading a file does not itself imply command execution |
| Upload field | Check server validation, storage location, rename behavior and execution handler | Upload accepted does not imply execution |
| System utility exposed through a form | Compare a harmless marker/identity result with baseline | A reflected input alone |
| Search/login parameter with SQL behavior | Paired true/false tests, then database-specific manual investigation | One slow response or generic database error |
| Reflected/stored browser input | Identify HTML/attribute/script context; use a benign marker in your lab | Text appearing in the source without execution |
| API object identifier | Compare authorized access with a second test account you control | Guessing identifiers without permission evidence |

For SQL injection, identify database syntax and column/type compatibility before a UNION test. For blind behavior, alternate control and test requests several times; network jitter can imitate a time delay. Database login, file-read privileges, file-write privileges and OS execution are separate capabilities. Use [the manual SQL notes](../README.md#sql-injection); SQLMap is excluded from the exam workflow.

## From application access to an operating-system shell

Before choosing an execution method, establish the OS, service account, writable location and available runtime. Test an identity command first. Confirm the callback destination is reachable from the target; an internal target may need the pivot's listener address. Save the exact request that triggered execution, then verify the resulting shell identity.

## Exploit adaptation checklist

- [ ] Product/version and vulnerable feature match the target evidence.
- [ ] Authentication, cookies, CSRF handling and virtual host are correct.
- [ ] Script supports the local interpreter and target architecture.
- [ ] Hardcoded scheme, port, endpoint, callback and filesystem path are reviewed.
- [ ] Shell quoting and URL/form/JSON encoding are handled at the correct layer.
- [ ] Original source, modifications, command and result are recorded.

Practice request replay with [Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater). Use the vendor's [Web Security Academy](https://portswigger.net/web-security) for controlled exercises. Review failures with [the troubleshooting guide](troubleshooting.md).
