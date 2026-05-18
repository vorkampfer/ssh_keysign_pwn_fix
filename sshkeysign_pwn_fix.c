/*
 * Temporary mitigation helper for sshkeysign/chage pidfd_getfd exposure.
 *
 * This is not a kernel fix. Use this only as an operational hardening step
 * until the kernel patch is installed.
 *
 * Modes:
 *   status   : show current risk and mitigation state
 *   apply    : remove setuid/setgid from known risky binaries and tighten
 *              ptrace policy (kernel.yama.ptrace_scope=3)
 *   rollback : restore original binary modes and ptrace scope from state file
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#define STATE_FILE "/var/lib/sshkeysign-pwn-fix/state"
#define SYSCTL_FILE "/etc/sysctl.d/99-sshkeysign-pwn-fix.conf"

struct target {
	const char *path;
	const char *name;
};

static const struct target TARGETS[] = {
	{ "/usr/libexec/ssh-keysign", "ssh-keysign" },
	{ "/usr/libexec/openssh/ssh-keysign", "ssh-keysign" },
	{ "/usr/lib/ssh/ssh-keysign", "ssh-keysign" },
	{ "/usr/lib/openssh/ssh-keysign", "ssh-keysign" },
	{ "/usr/bin/chage", "chage" },
	{ NULL, NULL },
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <mode>\n"
		"\n"
		"Modes:\n"
		"  status          Show current mitigation and risk state\n"
		"  check-patch     Heuristic check for likely patched kernel status\n"
		"  --apply-fullfix Full hardening (includes ssh-keysign + chage + ptrace)\n"
		"                 : warns and requires interactive y/yes confirmation\n"
		"  apply           Alias of --apply-fullfix (kept for compatibility)\n"
		"  apply-low-risk  Safer hardening (chage + ptrace only)\n"
		"  rollback        Restore state saved by apply/apply-low-risk\n"
		"  help            Show this help\n"
		"\n"
		"Examples:\n"
		"  sudo %s status\n"
		"  %s check-patch\n"
		"  sudo %s --apply-fullfix\n"
		"  sudo %s apply-low-risk\n"
		"  sudo %s rollback\n",
		prog, prog, prog, prog, prog, prog);
}

static int parse_release_triplet(const char *release, int *maj, int *min, int *pat)
{
	int a = 0;
	int b = 0;
	int c = 0;

	if (sscanf(release, "%d.%d.%d", &a, &b, &c) != 3)
		return -1;

	*maj = a;
	*min = b;
	*pat = c;
	return 0;
}

static int compare_triplet(int a1, int b1, int c1, int a2, int b2, int c2)
{
	if (a1 != a2)
		return (a1 > a2) ? 1 : -1;
	if (b1 != b2)
		return (b1 > b2) ? 1 : -1;
	if (c1 != c2)
		return (c1 > c2) ? 1 : -1;
	return 0;
}

static int do_check_patch(void)
{
	struct utsname u;
	int maj;
	int min;
	int pat;
	bool distro_kernel = false;

	if (uname(&u) < 0) {
		perror("uname");
		return 1;
	}

	printf("== kernel patch heuristic (CVE-2026-46333) ==\n");
	printf("[check] uname -r: %s\n", u.release);
	printf("[check] uname -v: %s\n", u.version);

	if (strstr(u.release, "ubuntu") || strstr(u.release, "debian") || strstr(u.release, "el") ||
	    strstr(u.release, "amzn") || strstr(u.release, "suse") || strstr(u.release, "generic") ||
	    strstr(u.release, "arch")) {
		distro_kernel = true;
	}

	if (parse_release_triplet(u.release, &maj, &min, &pat) != 0) {
		puts("[result] unknown: could not parse kernel version triplet");
		puts("[note] Use distro changelog/security advisories for CVE-2026-46333 confirmation.");
		return 0;
	}

	if (!distro_kernel && compare_triplet(maj, min, pat, 7, 0, 7) >= 0) {
		puts("[result] likely patched (upstream-style version is >= 7.0.7)");
		puts("[note] Still verify with your distro/kernel changelog if this is not official mainline.");
		return 0;
	}

	if (!distro_kernel && compare_triplet(maj, min, pat, 7, 0, 7) < 0) {
		puts("[result] likely vulnerable unless your vendor backported the fix");
		puts("[note] Keep mitigations enabled and verify package changelog for CVE-2026-46333.");
		return 0;
	}

	if (compare_triplet(maj, min, pat, 7, 0, 7) >= 0)
		puts("[result] likely patched, but distro backport policy means verify anyway");
	else
		puts("[result] unknown-to-risky: version alone is not enough on distro kernels; assume risk until verified");

	puts("[note] Check vendor changelog/security notice for CVE-2026-46333 or commit 31e62c2ebbfd backport.");
	return 0;
}

static bool confirm_full_apply(void)
{
	char answer[32];

	fprintf(stderr,
		"[warning] Full mitigation may affect SSH hostbased workflows by modifying ssh-keysign permissions.\n"
		"[warning] If you have any doubts, use apply-low-risk instead.\n"
		"Type y or yes to proceed: ");

	if (!fgets(answer, sizeof(answer), stdin))
		return false;

	answer[strcspn(answer, "\r\n")] = '\0';
	if (strcasecmp(answer, "y") == 0 || strcasecmp(answer, "yes") == 0)
		return true;

	puts("[apply] aborted by user");
	return false;
}

static bool is_root(void)
{
	return geteuid() == 0;
}

static int ensure_state_dir(void)
{
	struct stat st;
	if (stat("/var/lib/sshkeysign-pwn-fix", &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			fprintf(stderr, "[!] /var/lib/sshkeysign-pwn-fix exists but is not a directory\n");
			return -1;
		}
		return 0;
	}

	if (mkdir("/var/lib/sshkeysign-pwn-fix", 0700) < 0) {
		perror("mkdir /var/lib/sshkeysign-pwn-fix");
		return -1;
	}
	return 0;
}

static int read_ptrace_scope(void)
{
	FILE *f = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
	int v = -1;
	if (!f)
		return -1;
	if (fscanf(f, "%d", &v) != 1)
		v = -1;
	fclose(f);
	return v;
}

static int write_ptrace_scope(int value)
{
	FILE *f = fopen("/proc/sys/kernel/yama/ptrace_scope", "w");
	if (!f) {
		perror("open /proc/sys/kernel/yama/ptrace_scope");
		return -1;
	}
	if (fprintf(f, "%d\n", value) < 0) {
		perror("write ptrace_scope");
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

static int write_sysctl_dropin(void)
{
	FILE *f = fopen(SYSCTL_FILE, "w");
	if (!f) {
		perror("open sysctl drop-in");
		return -1;
	}
	fputs("# Temporary hardening for sshkeysign/chage pidfd_getfd exposure\n", f);
	fputs("# Remove after kernel update includes the mm-NULL ptrace fix.\n", f);
	fputs("kernel.yama.ptrace_scope = 3\n", f);
	fclose(f);
	return 0;
}

static int remove_sysctl_dropin(void)
{
	if (unlink(SYSCTL_FILE) < 0 && errno != ENOENT) {
		perror("unlink sysctl drop-in");
		return -1;
	}
	return 0;
}

static void check_ioc_passwd(void)
{
	FILE *f = fopen("/etc/passwd", "r");
	char line[1024];

	if (!f) {
		perror("open /etc/passwd");
		return;
	}

	printf("\n[IOC] UID 0 accounts in /etc/passwd:\n");
	while (fgets(line, sizeof(line), f)) {
		char copy[1024];
		char *user;
		char *x;
		char *uid;
		char *save;

		strncpy(copy, line, sizeof(copy) - 1);
		copy[sizeof(copy) - 1] = '\0';

		user = strtok_r(copy, ":", &save);
		x = strtok_r(NULL, ":", &save);
		uid = strtok_r(NULL, ":", &save);
		(void)x;

		if (user && uid && atoi(uid) == 0)
			printf("  - %s", line);
	}
	fclose(f);
}

static void show_target_state(void)
{
	for (int i = 0; TARGETS[i].path; i++) {
		struct stat st;
		if (stat(TARGETS[i].path, &st) < 0) {
			printf("[status] %-11s %s : not found\n", TARGETS[i].name, TARGETS[i].path);
			continue;
		}

		printf("[status] %-11s %s : mode=%04o%s%s\n",
		       TARGETS[i].name,
		       TARGETS[i].path,
		       st.st_mode & 07777,
		       (st.st_mode & S_ISUID) ? " suid" : "",
		       (st.st_mode & S_ISGID) ? " sgid" : "");
	}
}

static int do_status(void)
{
	int scope = read_ptrace_scope();

	puts("== sshkeysign-pwn mitigation status ==");
	show_target_state();

	if (scope >= 0)
		printf("[status] kernel.yama.ptrace_scope = %d\n", scope);
	else
		puts("[status] kernel.yama.ptrace_scope unavailable on this kernel");

	if (access(STATE_FILE, R_OK) == 0)
		printf("[status] state file present: %s\n", STATE_FILE);
	else
		printf("[status] state file missing: %s\n", STATE_FILE);

	if (access(SYSCTL_FILE, R_OK) == 0)
		printf("[status] sysctl drop-in present: %s\n", SYSCTL_FILE);
	else
		printf("[status] sysctl drop-in missing: %s\n", SYSCTL_FILE);

	check_ioc_passwd();
	return 0;
}

static int do_apply(bool low_risk)
{
	FILE *state;
	int scope_before;

	if (!is_root()) {
		fprintf(stderr, "[!] apply requires root\n");
		return 1;
	}

	if (!low_risk && !confirm_full_apply())
		return 1;

	if (ensure_state_dir() < 0)
		return 1;

	state = fopen(STATE_FILE, "w");
	if (!state) {
		perror("open state file");
		return 1;
	}

	scope_before = read_ptrace_scope();
	fprintf(state, "ptrace_scope_before=%d\n", scope_before);

	for (int i = 0; TARGETS[i].path; i++) {
		struct stat st;
		mode_t new_mode;

		/* Low-risk mode avoids touching ssh-keysign to reduce SSH breakage risk. */
		if (low_risk && strcmp(TARGETS[i].name, "ssh-keysign") == 0)
			continue;

		if (stat(TARGETS[i].path, &st) < 0) {
			fprintf(state, "missing=%s\n", TARGETS[i].path);
			continue;
		}

		fprintf(state, "mode=%s:%04o\n", TARGETS[i].path, st.st_mode & 07777);
		new_mode = st.st_mode & ~(S_ISUID | S_ISGID);
		if (new_mode != st.st_mode) {
			if (chmod(TARGETS[i].path, new_mode & 07777) < 0) {
				fprintf(stderr, "[!] chmod failed for %s: %s\n", TARGETS[i].path, strerror(errno));
			} else {
				printf("[apply] removed suid/sgid from %s\n", TARGETS[i].path);
			}
		} else {
			printf("[apply] no suid/sgid on %s\n", TARGETS[i].path);
		}
	}

	fclose(state);

	if (write_ptrace_scope(3) == 0)
		puts("[apply] set kernel.yama.ptrace_scope=3 (runtime)");
	else
		puts("[apply] could not set ptrace_scope at runtime");

	if (write_sysctl_dropin() == 0)
		printf("[apply] wrote persistent sysctl drop-in: %s\n", SYSCTL_FILE);

	if (low_risk)
		puts("[apply] low-risk mode: ssh-keysign permissions were not modified");

	puts("[apply] complete. Reboot not required for file mode changes.");
	puts("[apply] kernel update is still required for full remediation.");
	return 0;
}

static int parse_saved_mode(const char *line, char *path, mode_t *mode)
{
	char mode_str[16];
	if (sscanf(line, "mode=%1023[^:]:%15s", path, mode_str) == 2) {
		char *endp = NULL;
		unsigned long val = strtoul(mode_str, &endp, 8);
		if (endp && *endp == '\0' && val <= 07777) {
			*mode = (mode_t)val;
			return 0;
		}
	}
	return -1;
}

static int do_rollback(void)
{
	FILE *state;
	char line[1200];
	int restore_scope = -1;

	if (!is_root()) {
		fprintf(stderr, "[!] rollback requires root\n");
		return 1;
	}

	state = fopen(STATE_FILE, "r");
	if (!state) {
		perror("open state file");
		return 1;
	}

	while (fgets(line, sizeof(line), state)) {
		if (strncmp(line, "ptrace_scope_before=", 20) == 0) {
			restore_scope = atoi(line + 20);
			continue;
		}

		if (strncmp(line, "mode=", 5) == 0) {
			char path[1024];
			mode_t mode;
			if (parse_saved_mode(line, path, &mode) == 0) {
				if (chmod(path, mode) < 0)
					fprintf(stderr, "[!] restore chmod failed for %s: %s\n", path, strerror(errno));
				else
					printf("[rollback] restored %s to %04o\n", path, mode);
			}
		}
	}

	fclose(state);

	if (restore_scope >= 0) {
		if (write_ptrace_scope(restore_scope) == 0)
			printf("[rollback] restored kernel.yama.ptrace_scope=%d\n", restore_scope);
		else
			puts("[rollback] could not restore ptrace_scope runtime value");
	}

	remove_sysctl_dropin();
	if (unlink(STATE_FILE) < 0 && errno != ENOENT)
		perror("unlink state file");

	puts("[rollback] complete");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
		usage(argv[0]);
		return 0;
	}

	if (strcmp(argv[1], "status") == 0)
		return do_status();
	if (strcmp(argv[1], "check-patch") == 0)
		return do_check_patch();
	if (strcmp(argv[1], "apply") == 0 || strcmp(argv[1], "--apply-fullfix") == 0)
		return do_apply(false);
	if (strcmp(argv[1], "apply-low-risk") == 0)
		return do_apply(true);
	if (strcmp(argv[1], "rollback") == 0)
		return do_rollback();

	usage(argv[0]);
	return 1;
}
