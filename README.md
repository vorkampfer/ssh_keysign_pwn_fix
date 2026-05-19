# ssh_keysign_pwn_fix
### Mitigation against ssh-keysign-pwn until official kernel fix. Fix applies to Arch, Debian/Ubuntu platforms
### GitHub advisory: [GHSA-pm8f-4p6p-6x53](https://github.com/advisories/GHSA-pm8f-4p6p-6x53)

Small C utility for temporary hardening against recent pidfd_getfd-based local file-descriptor theft chains.

## What it does
- `status`: shows risk/mitigation state.
- `check-patch`: heuristically checks whether your running kernel is likely patched.
- `apply-low-risk`: hardens ptrace + chage path (safer for SSH users).
- `--apply-fullfix`: full hardening, warns and requires `y/yes` confirmation.
- `rollback`: restores saved file modes and ptrace scope.

## Important
- This is a temporary mitigation, not a kernel vulnerability fix.
- Main fix is updating to a patched kernel.
- Use `apply-low-risk` first if you are worried about SSH behavior.

## Build
```
gcc -Wall -Wextra -Werror -O2 sshkeysign_pwn_fix.c -o sshkeysign_pwn_fix
```
## Example:
```
ᐅ sudo ./sshkeysign_pwn_fix apply-low-risk
[apply] removed suid/sgid from /usr/bin/chage
[apply] set kernel.yama.ptrace_scope=3 (runtime)
[apply] wrote persistent sysctl drop-in: /etc/sysctl.d/99-sshkeysign-pwn-fix.conf
[apply] low-risk mode: ssh-keysign permissions were not modified
[apply] complete. Reboot not required for file mode changes.
[apply] kernel update is still required for full remediation.

ᐅ ./sshkeysign_pwn_fix status
== sshkeysign-pwn mitigation status ==
[Note] Linux Kernel 7.0.8 is Released to Fix ssh-keysign-pwn Root Exploitation (CVE-2026-46333)
[status-flag] kernel-fix-threshold-not-met (< 7.0.8): 7.0.7-arch2-1
[status] ssh-keysign /usr/libexec/ssh-keysign : not found
[status] ssh-keysign /usr/libexec/openssh/ssh-keysign : not found
[status] ssh-keysign /usr/lib/ssh/ssh-keysign : mode=4711 suid
[status] ssh-keysign /usr/lib/openssh/ssh-keysign : not found
[status] chage       /usr/bin/chage : mode=0755
[status] kernel.yama.ptrace_scope = 3
[status] state file missing: /var/lib/sshkeysign-pwn-fix/state
[status] sysctl drop-in present: /etc/sysctl.d/99-sshkeysign-pwn-fix.conf

[IOC] UID 0 accounts in /etc/passwd:
  - root:x:0:0::/root:/usr/bin/nologin
```
