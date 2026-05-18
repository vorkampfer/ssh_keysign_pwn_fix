# ssh_keysign_pwn_fix
### Mitigation against ssh-keysign-pwn until official kernel fix. Fix applies to Arch, Debian/Ubuntu platforms
### Small C utility for temporary hardening against recent pidfd_getfd-based local file-descriptor theft chains.

## What it does
- `status`: shows risk/mitigation state.
- `apply-low-risk`: hardens ptrace + chage path (safer for SSH users).
- `--apply-fullfix`: full hardening, warns and requires `y/yes` confirmation.
- `rollback`: restores saved file modes and ptrace scope.

## Important
- This is a temporary mitigation, not a kernel vulnerability fix.
- Main fix is updating to a patched kernel.
- Use `apply-low-risk` first if you are worried about SSH behavior.

## Build
`gcc -Wall -Wextra -Werror -O2 sshkeysign_pwn_fix.c -o sshkeysign_pwn_fix`
