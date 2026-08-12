/*
 * Kizashi — Windows pre-execution prevention driver (PoC) — shared defs.
 *
 * Mirrors the Linux eBPF LSM model: a kernel callback denies execve of
 * blocklisted images; per-path mode (audit / enforce-eligible) + a global
 * enforce switch + fail-open default. This header is shared between the kernel
 * driver (prevention.c) and the user-mode control program.
 *
 * STATUS: PoC. Builds with the WDK (kernel side). NOT yet compiled/tested on
 * hardware — must be test-signed and loaded on a test-mode Windows VM before any
 * claim that it works. See docs/Windowsカーネル防御PoC手順.md.
 */
#ifndef KIZASHI_PREVENTION_H
#define KIZASHI_PREVENTION_H

/* User-mode opens \\.\KizashiPrevention; kernel creates the device + symlink. */
#define PREV_DEVICE_NAME    L"\\Device\\KizashiPrevention"
#define PREV_SYMLINK_NAME   L"\\??\\KizashiPrevention"
#define PREV_USERMODE_PATH  L"\\\\.\\KizashiPrevention"

#define PREV_MAX_PATH       260
#define PREV_MAX_RULES      512

/* Per-path mode (mirrors Linux PathModeAudit/PathModeEnforce). */
#define PREV_MODE_AUDIT     1u  /* report only, never deny */
#define PREV_MODE_ENFORCE   2u  /* deny when the global enforce switch is on */

/* One blocklist rule pushed from user mode. Match is case-insensitive suffix
 * of the image's NT path (the kernel sees an NT path; user mode knows the DOS
 * path — suffix match bridges that for the PoC; refine to full normalization
 * later, same NT->DOS lesson as Linux #219). */
typedef struct _PREV_RULE {
    unsigned short PathLen;            /* number of WCHARs in Path (no NUL) */
    unsigned int   Mode;               /* PREV_MODE_* */
    wchar_t        Path[PREV_MAX_PATH];/* e.g. L"\\blockme.exe" or full path tail */
} PREV_RULE;

/* Global config: enforce switch (0 = audit-all / fail-open, 1 = enforce). */
typedef struct _PREV_CONFIG {
    unsigned int Enforce;
} PREV_CONFIG;

/* A decision the driver made, pulled by user mode for the audit log. */
typedef struct _PREV_DECISION {
    unsigned int ProcessId;
    unsigned int Blocked;   /* 1 = matched a rule */
    unsigned int Enforced;  /* 1 = creation actually denied (STATUS_ACCESS_DENIED) */
    wchar_t      Path[PREV_MAX_PATH];
} PREV_DECISION;

/* ── Tamper protection (W4a) ──────────────────────────────────────────────────
 * Agent self-protection: an ObRegisterCallbacks pre-operation callback strips
 * dangerous access (PROCESS_TERMINATE etc.) from handles opened to the protected
 * agent PID. The Windows counterpart of the Linux eBPF LSM task_kill deny — same
 * audit→enforce / fail-open / disarm model. Disarm + stopping the driver service
 * are the escape hatches so an operator can always stop/update the agent. */

/* Global tamper config: enforce switch + disarm (temporary allow) escape hatch. */
typedef struct _PREV_TAMPER_CONFIG {
    unsigned int Enforce;   /* 0 = audit-only (fail-open), 1 = enforce (strip access) */
    unsigned int Disarm;    /* 1 = temporarily allow kills (operator stop/update)     */
} PREV_TAMPER_CONFIG;

/* Register the PID to protect (the agent's own PID). Mode is PREV_MODE_*. */
typedef struct _PREV_PROTECT {
    unsigned int Pid;
    unsigned int Mode;      /* PREV_MODE_ENFORCE = strip when enforce on; AUDIT = report only */
} PREV_PROTECT;

/* A tamper decision pulled by user mode for the audit log. */
typedef struct _PREV_TAMPER_DECISION {
    unsigned int TargetPid; /* the protected process a handle was opened to */
    unsigned int SenderPid; /* the process that opened the handle           */
    unsigned int Enforced;  /* 1 = dangerous access actually stripped       */
    unsigned int Access;    /* the originally requested DesiredAccess        */
} PREV_TAMPER_DECISION;

/* IOCTLs (METHOD_BUFFERED, require write access). */
#define PREV_IOCTL_BASE 0x800
#define PREV_IOCTL_SET_ENFORCE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PREV_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define PREV_IOCTL_ADD_RULE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PREV_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define PREV_IOCTL_CLEAR_RULES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PREV_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define PREV_IOCTL_GET_DECISION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PREV_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/* Tamper protection (W4a) IOCTLs. */
#define PREV_IOCTL_SET_TAMPER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PREV_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define PREV_IOCTL_PROTECT_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PREV_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define PREV_IOCTL_GET_TAMPER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PREV_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/* Injection telemetry (M2) IOCTLs. SET enables cross-process injection audit
 * (uses PREV_CONFIG.Enforce as the on/off flag); GET pulls injection decisions
 * (reuses PREV_TAMPER_DECISION: TargetPid=victim, SenderPid=injector, Enforced=0
 * (audit), Access=requested access, or 0xFFFFFFFF for a remote-thread creation). */
#define PREV_IOCTL_SET_INJECT_AUDIT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PREV_IOCTL_BASE + 8, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define PREV_IOCTL_GET_INJECT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PREV_IOCTL_BASE + 9, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/* Credential-access / LSASS detection (M3) IOCTLs. A handle opened to lsass.exe
 * requesting PROCESS_VM_READ is the access credential-dumping tools (mimikatz,
 * procdump) use to read LSASS memory (ATT&CK T1003.001) — the user-mode analog
 * of Sysmon EventID 10, but real-time and from our own ObRegisterCallbacks.
 * SET_LSASS_PID registers the lsass PID to watch (PREV_PROTECT: Pid + Mode);
 * SET_CRED toggles enforce (PREV_TAMPER_CONFIG: strip VM_READ when on);
 * GET_CRED pulls decisions (PREV_TAMPER_DECISION: TargetPid=lsass,
 * SenderPid=accessor, Enforced, Access=requested DesiredAccess). */
#define PREV_IOCTL_SET_LSASS_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PREV_IOCTL_BASE + 10, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define PREV_IOCTL_SET_CRED \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PREV_IOCTL_BASE + 11, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define PREV_IOCTL_GET_CRED \
    CTL_CODE(FILE_DEVICE_UNKNOWN, PREV_IOCTL_BASE + 12, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#endif /* KIZASHI_PREVENTION_H */
