# Security policy

## Supported versions

Security fixes are applied to the latest tagged release and the default branch. Older releases may receive a fix when the affected code is still compatible, but there is no guaranteed long-term support branch.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository: open the **Security** tab, choose **Advisories**, then **Report a vulnerability**. Do not create a public issue for an unpatched vulnerability.

Include:

- affected version or commit;
- Windows version and target architecture;
- a minimal reproducer or malformed request;
- expected and observed behavior;
- crash details, stack trace, and debugger output where available;
- whether the issue crosses a trust boundary or requires an already privileged local user.

Avoid sending secrets, proprietary binaries, or third-party memory dumps. A synthetic fixture is preferred.

You should receive an acknowledgement within seven days. Validation, fix, and disclosure timing depend on severity and reproducibility. Please allow a reasonable remediation window before public disclosure.

## Trust model

ReverseMCP is a local tool with the privileges of the account that starts it. It does not authenticate stdio clients. The launcher is responsible for deciding which client may start the server and which tool calls require confirmation.

Opening a binary is intended to be passive and read-only. Attaching to a process exposes its readable memory to the client. `write_memory` and debugger tools can change a target's memory or execution state. Do not expose the server to untrusted remote input or run it with privileges the target does not require.

Cache files under `%LOCALAPPDATA%/ReversePlugin` may contain analyst names, comments, type declarations, and derived facts about inspected binaries. Protect or remove that directory according to the sensitivity of the investigation.
