/*
 * Kizashi — Windows pre-execution prevention driver (PoC).
 *
 * Registers a process-creation callback (PsSetCreateProcessNotifyRoutineEx) and,
 * for blocklisted images, denies creation by setting CreateInfo->CreationStatus
 * = STATUS_ACCESS_DENIED. This is the Windows counterpart to the Linux eBPF LSM
 * bprm_check_security hook. Per-path mode (audit/enforce-eligible) + a global
 * enforce switch + fail-open default mirror the Linux design.
 *
 * Rules and the enforce switch are pushed from user mode via IOCTLs on the
 * control device \\.\KizashiPrevention. Decisions are queued for the user-mode
 * agent to pull (PREV_IOCTL_GET_DECISION) and surface as process_block events.
 *
 * BUILD: WDK (KMDF/WDM). Must be linked with /INTEGRITYCHECK and signed; the
 * process-notify callback registration requires it. Test-sign + test-mode VM to
 * load. See docs/Windowsカーネル防御PoC手順.md.
 *
 * ⚠️ STATUS: PoC, NOT compiled/loaded on hardware yet. Kernel bugs BSOD — verify
 * on a disposable test-mode VM only.
 */
/* ntifs.h (superset of ntddk.h) is required for PsProcessType, used by the
 * tamper ObRegisterCallbacks path. It also provides everything ntddk.h does. */
#include <ntifs.h>
#include "prevention.h"

/* Exported by ntoskrnl (Windows 8+) but not declared in every WDK's ntifs.h.
 * Declared manually so the M2 ThreadNotify can resolve a target process's parent
 * PID to exclude the benign parent->child initial-thread case. */
NTKERNELAPI HANDLE NTAPI PsGetProcessInheritedFromUniqueProcessId(PEPROCESS Process);

/* Process-object access rights (PROCESS_*) live in user-mode winnt.h, not in the
 * kernel headers, so the tamper callback (which masks them off) must define the
 * ones it uses. Values per the Windows ABI. */
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE       0x0001
#define PROCESS_CREATE_THREAD   0x0002
#define PROCESS_VM_OPERATION    0x0008
#define PROCESS_VM_READ         0x0010
#define PROCESS_VM_WRITE        0x0020
#define PROCESS_SUSPEND_RESUME  0x0800
#define PROCESS_SET_INFORMATION 0x0200
#endif

/* ── Global state (non-paged; touched from the create callback) ───────────── */

typedef struct _PREV_STATE {
    PDEVICE_OBJECT Device;
    KSPIN_LOCK     Lock;
    ULONG          Enforce;                 /* 0 = audit-all (fail-open), 1 = enforce */
    ULONG          RuleCount;
    PREV_RULE      Rules[PREV_MAX_RULES];
    /* tiny decision ring */
    PREV_DECISION  Dec[256];
    ULONG          DecHead;                 /* next write */
    ULONG          DecTail;                 /* next read */
    BOOLEAN        CallbackRegistered;

    /* ── Tamper protection (W4a) ── */
    ULONG                 TamperEnforce;    /* 0 = audit, 1 = enforce (strip access) */
    ULONG                 TamperDisarm;     /* 1 = temporarily allow kills           */
    ULONG                 ProtectedPid;     /* the agent PID to protect (0 = none)   */
    ULONG                 ProtectedMode;    /* PREV_MODE_* for the protected PID      */
    PVOID                 ObHandle;         /* ObRegisterCallbacks registration       */
    BOOLEAN               ObRegistered;
    PREV_TAMPER_DECISION  TDec[128];        /* tamper decision ring                   */
    ULONG                 TDecHead;
    ULONG                 TDecTail;

    /* ── Injection telemetry (M2) ── */
    ULONG                 InjectAudit;      /* 1 = audit cross-process injection ops  */
    BOOLEAN               ThreadCbRegistered;
    PREV_TAMPER_DECISION  IDec[128];        /* injection decision ring (same shape)   */
    ULONG                 IDecHead;
    ULONG                 IDecTail;

    /* ── Credential-access / LSASS detection (M3) ── */
    ULONG                 LsassPid;         /* lsass.exe PID to watch (0 = disabled)  */
    ULONG                 LsassMode;        /* PREV_MODE_* for the lsass watch         */
    ULONG                 CredEnforce;      /* 1 = strip VM_READ to lsass (enforce)    */
    PREV_TAMPER_DECISION  CDec[128];        /* credential-access decision ring         */
    ULONG                 CDecHead;
    ULONG                 CDecTail;
} PREV_STATE;

static PREV_STATE g;

#define DEC_CAP  (ARRAYSIZE(g.Dec))
#define TDEC_CAP (ARRAYSIZE(g.TDec))
#define IDEC_CAP (ARRAYSIZE(g.IDec))
#define CDEC_CAP (ARRAYSIZE(g.CDec))

/* Access that, when requested against lsass, indicates credential dumping: a
 * read of LSASS memory (mimikatz/procdump open lsass with PROCESS_VM_READ). */
#define PREV_CRED_ACCESS (PROCESS_VM_READ)

/* Access that, when requested cross-process, indicates an injection attempt
 * (write to / create thread in / operate on another process's memory). */
#define PREV_INJECT_ACCESS \
    (PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION)

/* Sentinel Access value in an injection decision meaning "remote thread created". */
#define PREV_INJECT_REMOTE_THREAD 0xFFFFFFFF

/* Access bits stripped from handles to the protected agent when enforcing — the
 * ones that allow killing, code injection, or suspension. */
#define PREV_TAMPER_STRIP \
    (PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | \
     PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION)

/* ── Helpers ──────────────────────────────────────────────────────────────── */

/* Case-insensitive suffix match: does image (NT path) end with rule (DOS tail)?
 * The kernel sees an NT path while user mode knows the DOS path; a suffix match
 * bridges that for the PoC (refine to full NT->DOS normalization later). */
static BOOLEAN ImageMatchesRule(PCUNICODE_STRING image, const PREV_RULE *rule)
{
    UNICODE_STRING tail, pat;
    USHORT patBytes;

    if (image == NULL || image->Buffer == NULL || rule->PathLen == 0)
        return FALSE;

    patBytes = (USHORT)(rule->PathLen * sizeof(WCHAR));
    if (image->Length < patBytes)
        return FALSE;

    /* tail = last patBytes of image */
    tail.Buffer = (PWCH)((PUCHAR)image->Buffer + (image->Length - patBytes));
    tail.Length = patBytes;
    tail.MaximumLength = patBytes;

    pat.Buffer = (PWCH)rule->Path;
    pat.Length = patBytes;
    pat.MaximumLength = patBytes;

    return RtlCompareUnicodeString(&tail, &pat, TRUE) == 0; /* TRUE = case-insensitive */
}

static void QueueDecision(ULONG pid, BOOLEAN enforced, PCUNICODE_STRING image)
{
    PREV_DECISION *d;
    USHORT n;

    /* caller holds g.Lock */
    d = &g.Dec[g.DecHead % DEC_CAP];
    RtlZeroMemory(d, sizeof(*d));
    d->ProcessId = pid;
    d->Blocked = 1;
    d->Enforced = enforced ? 1 : 0;
    if (image && image->Buffer) {
        n = image->Length / sizeof(WCHAR);
        if (n >= PREV_MAX_PATH) n = PREV_MAX_PATH - 1;
        RtlCopyMemory(d->Path, image->Buffer, n * sizeof(WCHAR));
        d->Path[n] = L'\0';
    }
    g.DecHead++;
    if (g.DecHead - g.DecTail > DEC_CAP)
        g.DecTail = g.DecHead - DEC_CAP; /* drop oldest on overflow */
}

static void QueueTamperDecision(ULONG targetPid, ULONG senderPid, BOOLEAN enforced, ACCESS_MASK access)
{
    PREV_TAMPER_DECISION *d;

    /* caller holds g.Lock */
    d = &g.TDec[g.TDecHead % TDEC_CAP];
    d->TargetPid = targetPid;
    d->SenderPid = senderPid;
    d->Enforced  = enforced ? 1 : 0;
    d->Access    = (ULONG)access;
    g.TDecHead++;
    if (g.TDecHead - g.TDecTail > TDEC_CAP)
        g.TDecTail = g.TDecHead - TDEC_CAP; /* drop oldest on overflow */
}

static void QueueInjectDecision(ULONG targetPid, ULONG senderPid, ACCESS_MASK access)
{
    PREV_TAMPER_DECISION *d;

    /* caller holds g.Lock */
    d = &g.IDec[g.IDecHead % IDEC_CAP];
    d->TargetPid = targetPid;
    d->SenderPid = senderPid;
    d->Enforced  = 0; /* audit only */
    d->Access    = (ULONG)access;
    g.IDecHead++;
    if (g.IDecHead - g.IDecTail > IDEC_CAP)
        g.IDecTail = g.IDecHead - IDEC_CAP; /* drop oldest on overflow */
}

static void QueueCredDecision(ULONG targetPid, ULONG senderPid, BOOLEAN enforced, ACCESS_MASK access)
{
    PREV_TAMPER_DECISION *d;

    /* caller holds g.Lock */
    d = &g.CDec[g.CDecHead % CDEC_CAP];
    d->TargetPid = targetPid;
    d->SenderPid = senderPid;
    d->Enforced  = enforced ? 1 : 0;
    d->Access    = (ULONG)access;
    g.CDecHead++;
    if (g.CDecHead - g.CDecTail > CDEC_CAP)
        g.CDecTail = g.CDecHead - CDEC_CAP; /* drop oldest on overflow */
}

/* ── Injection telemetry (M2): remote-thread creation ─────────────────────────
 * A thread created in a process by a *different* process is the classic
 * CreateRemoteThread injection. Audit only (no block). */
static VOID ThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    KIRQL irql;
    ULONG injectAudit, targetPid, senderPid;

    UNREFERENCED_PARAMETER(ThreadId);
    if (!Create)
        return;
    targetPid = (ULONG)(ULONG_PTR)ProcessId;
    senderPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (senderPid == targetPid || senderPid == 0)
        return; /* local thread — normal */

    /* Exclude the benign parent->child launch. The INITIAL thread of a newly
     * created process is created by its parent, which at this callback is
     * indistinguishable from a CreateRemoteThread injection (sender != target) —
     * so every normal process launch (powershell -> systeminfo, -> certutil, ...)
     * was reported as a remote-thread injection. If the target's parent is the
     * sender, this is process creation, not injection; Sysmon EID8 excludes it
     * too. Checked in-kernel and race-free: the target process exists at
     * initial-thread time and its InheritedFromUniqueProcessId is set at creation
     * (works even for short-lived children the user-mode audit consumer would miss
     * because they exit before it can query them). */
    {
        PEPROCESS targetProc;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)targetPid, &targetProc))) {
            ULONG parentPid = (ULONG)(ULONG_PTR)PsGetProcessInheritedFromUniqueProcessId(targetProc);
            ObDereferenceObject(targetProc);
            if (parentPid == senderPid)
                return; /* initial thread of a child the sender spawned */
        }
    }

    KeAcquireSpinLock(&g.Lock, &irql);
    injectAudit = g.InjectAudit;
    if (injectAudit)
        QueueInjectDecision(targetPid, senderPid, PREV_INJECT_REMOTE_THREAD);
    KeReleaseSpinLock(&g.Lock, irql);
}

/* ── Tamper protection: process-handle pre-operation callback ──────────────────
 * Strips kill/inject/suspend access from handles being opened (or duplicated) to
 * the protected agent PID when tamper enforce is on and not disarmed. fail-open:
 * if not enforcing, it only records the attempt. The protected process opening a
 * handle to itself is never restricted. */
static OB_PREOP_CALLBACK_STATUS ProcessPreOp(PVOID ctx, POB_PRE_OPERATION_INFORMATION info)
{
    KIRQL irql;
    ULONG protectedPid, mode, enforce, disarm, targetPid, senderPid;
    PACCESS_MASK desired;
    ACCESS_MASK before;
    BOOLEAN enforced;

    ULONG injectAudit;
    ULONG lsassPid, lsassMode, credEnforce;

    UNREFERENCED_PARAMETER(ctx);

    if (info == NULL || info->KernelHandle)
        return OB_PREOP_SUCCESS; /* ignore kernel handles */
    if (info->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;

    targetPid = (ULONG)(ULONG_PTR)PsGetProcessId((PEPROCESS)info->Object);
    senderPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    if (info->Operation == OB_OPERATION_HANDLE_CREATE)
        desired = &info->Parameters->CreateHandleInformation.DesiredAccess;
    else
        desired = &info->Parameters->DuplicateHandleInformation.DesiredAccess;
    before = *desired;

    KeAcquireSpinLock(&g.Lock, &irql);
    protectedPid = g.ProtectedPid;
    mode         = g.ProtectedMode;
    enforce      = g.TamperEnforce;
    disarm       = g.TamperDisarm;
    injectAudit  = g.InjectAudit;
    lsassPid     = g.LsassPid;
    lsassMode    = g.LsassMode;
    credEnforce  = g.CredEnforce;
    KeReleaseSpinLock(&g.Lock, irql);

    /* ── M2 injection audit: any cross-process handle requesting injection-capable
     * access (write/create-thread/operate) to another process. Audit only.
     * Exclude the parent->child case: CreateProcess hands the parent a
     * PROCESS_ALL_ACCESS handle to the child it just spawned, which trips the
     * injection-access mask on every single process launch. If the target's parent
     * is the opener, this is process creation, not injection (the target EPROCESS
     * is in hand, so its InheritedFromUniqueProcessId is read directly). ── */
    if (injectAudit && senderPid != targetPid && senderPid != 0 &&
        (before & PREV_INJECT_ACCESS) != 0 &&
        (ULONG)(ULONG_PTR)PsGetProcessInheritedFromUniqueProcessId((PEPROCESS)info->Object) != senderPid) {
        KeAcquireSpinLock(&g.Lock, &irql);
        QueueInjectDecision(targetPid, senderPid, before);
        KeReleaseSpinLock(&g.Lock, irql);
    }

    /* ── M3 credential-access: a handle to lsass requesting VM_READ — the read of
     * LSASS memory used for credential dumping (T1003.001). Audit by default;
     * strip VM_READ when enforcing. ── */
    if (lsassPid != 0 && targetPid == lsassPid && senderPid != lsassPid &&
        senderPid != 0 && (before & PREV_CRED_ACCESS) != 0) {
        BOOLEAN credEnf = (credEnforce == 1 && lsassMode == PREV_MODE_ENFORCE);
        if (credEnf)
            *desired &= ~PREV_CRED_ACCESS; /* strip VM_READ so the dump fails */
        KeAcquireSpinLock(&g.Lock, &irql);
        QueueCredDecision(targetPid, senderPid, credEnf, before);
        KeReleaseSpinLock(&g.Lock, irql);
    }

    /* ── W4a tamper: protect the agent PID from kill/inject/suspend. ── */
    if (protectedPid == 0 || targetPid != protectedPid)
        return OB_PREOP_SUCCESS;       /* not our protected process */
    if (senderPid == protectedPid)
        return OB_PREOP_SUCCESS;       /* the agent opening itself — never restrict */

    enforced = (enforce == 1 && disarm == 0 && mode == PREV_MODE_ENFORCE &&
                (before & PREV_TAMPER_STRIP) != 0);
    if (enforced)
        *desired &= ~PREV_TAMPER_STRIP; /* strip kill/inject/suspend access */

    if ((before & PREV_TAMPER_STRIP) != 0) {
        KeAcquireSpinLock(&g.Lock, &irql);
        QueueTamperDecision(protectedPid, senderPid, enforced, before);
        KeReleaseSpinLock(&g.Lock, irql);
    }
    return OB_PREOP_SUCCESS;
}

/* ── Process-creation callback ────────────────────────────────────────────── */

static VOID ProcessNotifyEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    KIRQL irql;
    ULONG i;
    BOOLEAN deny = FALSE;
    PCUNICODE_STRING image;

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL)
        return; /* process exit — not our concern */

    image = CreateInfo->ImageFileName;
    if (image == NULL)
        return;

    KeAcquireSpinLock(&g.Lock, &irql);
    for (i = 0; i < g.RuleCount; i++) {
        if (ImageMatchesRule(image, &g.Rules[i])) {
            deny = (g.Enforce == 1 && g.Rules[i].Mode == PREV_MODE_ENFORCE);
            QueueDecision((ULONG)(ULONG_PTR)ProcessId, deny, image);
            break;
        }
    }
    KeReleaseSpinLock(&g.Lock, irql);

    if (deny) {
        /* Deny creation — the loader fails the process with this status. */
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    }
}

/* ── IOCTL dispatch ───────────────────────────────────────────────────────── */

static NTSTATUS DispatchCreateClose(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;
    KIRQL irql;
    PVOID buf = irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;

    UNREFERENCED_PARAMETER(dev);

    switch (sp->Parameters.DeviceIoControl.IoControlCode) {
    case PREV_IOCTL_SET_ENFORCE:
        if (inLen >= sizeof(PREV_CONFIG)) {
            PREV_CONFIG *c = (PREV_CONFIG *)buf;
            KeAcquireSpinLock(&g.Lock, &irql);
            g.Enforce = c->Enforce ? 1 : 0;
            KeReleaseSpinLock(&g.Lock, irql);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case PREV_IOCTL_ADD_RULE:
        if (inLen >= sizeof(PREV_RULE)) {
            PREV_RULE *r = (PREV_RULE *)buf;
            KeAcquireSpinLock(&g.Lock, &irql);
            if (g.RuleCount < PREV_MAX_RULES && r->PathLen > 0 && r->PathLen < PREV_MAX_PATH) {
                RtlCopyMemory(&g.Rules[g.RuleCount], r, sizeof(PREV_RULE));
                g.RuleCount++;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            KeReleaseSpinLock(&g.Lock, irql);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case PREV_IOCTL_CLEAR_RULES:
        KeAcquireSpinLock(&g.Lock, &irql);
        g.RuleCount = 0;
        KeReleaseSpinLock(&g.Lock, irql);
        status = STATUS_SUCCESS;
        break;

    case PREV_IOCTL_GET_DECISION:
        if (outLen >= sizeof(PREV_DECISION)) {
            KeAcquireSpinLock(&g.Lock, &irql);
            if (g.DecTail != g.DecHead) {
                RtlCopyMemory(buf, &g.Dec[g.DecTail % DEC_CAP], sizeof(PREV_DECISION));
                g.DecTail++;
                info = sizeof(PREV_DECISION);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_NO_MORE_ENTRIES;
            }
            KeReleaseSpinLock(&g.Lock, irql);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case PREV_IOCTL_SET_TAMPER:
        if (inLen >= sizeof(PREV_TAMPER_CONFIG)) {
            PREV_TAMPER_CONFIG *c = (PREV_TAMPER_CONFIG *)buf;
            KeAcquireSpinLock(&g.Lock, &irql);
            g.TamperEnforce = c->Enforce ? 1 : 0;
            g.TamperDisarm  = c->Disarm ? 1 : 0;
            KeReleaseSpinLock(&g.Lock, irql);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case PREV_IOCTL_PROTECT_PID:
        if (inLen >= sizeof(PREV_PROTECT)) {
            PREV_PROTECT *p = (PREV_PROTECT *)buf;
            KeAcquireSpinLock(&g.Lock, &irql);
            g.ProtectedPid  = p->Pid;
            g.ProtectedMode = p->Mode;
            KeReleaseSpinLock(&g.Lock, irql);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case PREV_IOCTL_GET_TAMPER:
        if (outLen >= sizeof(PREV_TAMPER_DECISION)) {
            KeAcquireSpinLock(&g.Lock, &irql);
            if (g.TDecTail != g.TDecHead) {
                RtlCopyMemory(buf, &g.TDec[g.TDecTail % TDEC_CAP], sizeof(PREV_TAMPER_DECISION));
                g.TDecTail++;
                info = sizeof(PREV_TAMPER_DECISION);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_NO_MORE_ENTRIES;
            }
            KeReleaseSpinLock(&g.Lock, irql);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case PREV_IOCTL_SET_INJECT_AUDIT:
        if (inLen >= sizeof(PREV_CONFIG)) {
            PREV_CONFIG *c = (PREV_CONFIG *)buf;
            KeAcquireSpinLock(&g.Lock, &irql);
            g.InjectAudit = c->Enforce ? 1 : 0;
            KeReleaseSpinLock(&g.Lock, irql);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case PREV_IOCTL_GET_INJECT:
        if (outLen >= sizeof(PREV_TAMPER_DECISION)) {
            KeAcquireSpinLock(&g.Lock, &irql);
            if (g.IDecTail != g.IDecHead) {
                RtlCopyMemory(buf, &g.IDec[g.IDecTail % IDEC_CAP], sizeof(PREV_TAMPER_DECISION));
                g.IDecTail++;
                info = sizeof(PREV_TAMPER_DECISION);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_NO_MORE_ENTRIES;
            }
            KeReleaseSpinLock(&g.Lock, irql);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case PREV_IOCTL_SET_LSASS_PID:
        if (inLen >= sizeof(PREV_PROTECT)) {
            PREV_PROTECT *p = (PREV_PROTECT *)buf;
            KeAcquireSpinLock(&g.Lock, &irql);
            g.LsassPid  = p->Pid;
            g.LsassMode = p->Mode;
            KeReleaseSpinLock(&g.Lock, irql);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case PREV_IOCTL_SET_CRED:
        if (inLen >= sizeof(PREV_TAMPER_CONFIG)) {
            PREV_TAMPER_CONFIG *c = (PREV_TAMPER_CONFIG *)buf;
            KeAcquireSpinLock(&g.Lock, &irql);
            g.CredEnforce = c->Enforce ? 1 : 0;
            KeReleaseSpinLock(&g.Lock, irql);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case PREV_IOCTL_GET_CRED:
        if (outLen >= sizeof(PREV_TAMPER_DECISION)) {
            KeAcquireSpinLock(&g.Lock, &irql);
            if (g.CDecTail != g.CDecHead) {
                RtlCopyMemory(buf, &g.CDec[g.CDecTail % CDEC_CAP], sizeof(PREV_TAMPER_DECISION));
                g.CDecTail++;
                info = sizeof(PREV_TAMPER_DECISION);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_NO_MORE_ENTRIES;
            }
            KeReleaseSpinLock(&g.Lock, irql);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

/* ── Driver lifecycle ─────────────────────────────────────────────────────── */

static VOID DriverUnload(PDRIVER_OBJECT drv)
{
    UNICODE_STRING symlink;
    UNREFERENCED_PARAMETER(drv);

    /* Unregistering the Ob callback is the hard tamper escape hatch: `sc stop`
     * removes protection so an operator can always stop/update the agent. */
    if (g.ObRegistered && g.ObHandle) {
        ObUnRegisterCallbacks(g.ObHandle);
        g.ObHandle = NULL;
        g.ObRegistered = FALSE;
    }

    if (g.ThreadCbRegistered)
        PsRemoveCreateThreadNotifyRoutine(ThreadNotify); /* M2 */

    if (g.CallbackRegistered)
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyEx, TRUE); /* TRUE = remove */

    RtlInitUnicodeString(&symlink, PREV_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);
    if (g.Device)
        IoDeleteDevice(g.Device);
}

/* RegisterTamperCallback registers the process-handle pre-operation callback used
 * for agent self-protection. Requires the driver to be signed (test-signed in a
 * test-mode VM) — the same requirement as the process-notify callback. A failure
 * is non-fatal: prevention still works, tamper protection is just unavailable. */
static NTSTATUS RegisterTamperCallback(void)
{
    OB_OPERATION_REGISTRATION op;
    OB_CALLBACK_REGISTRATION  cb;
    UNICODE_STRING            altitude;

    RtlZeroMemory(&op, sizeof(op));
    op.ObjectType        = PsProcessType;
    op.Operations        = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    op.PreOperation      = ProcessPreOp;
    op.PostOperation     = NULL;

    RtlInitUnicodeString(&altitude, L"320520"); /* unique altitude for this filter */

    RtlZeroMemory(&cb, sizeof(cb));
    cb.Version                    = OB_FLT_REGISTRATION_VERSION;
    cb.OperationRegistrationCount = 1;
    cb.Altitude                   = altitude;
    cb.RegistrationContext        = NULL;
    cb.OperationRegistration      = &op;

    return ObRegisterCallbacks(&cb, &g.ObHandle);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    NTSTATUS status;
    UNICODE_STRING devName, symlink;
    UNREFERENCED_PARAMETER(reg);

    RtlZeroMemory(&g, sizeof(g));
    KeInitializeSpinLock(&g.Lock);

    RtlInitUnicodeString(&devName, PREV_DEVICE_NAME);
    status = IoCreateDevice(drv, 0, &devName, FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &g.Device);
    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&symlink, PREV_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g.Device);
        return status;
    }

    drv->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    drv->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    drv->DriverUnload = DriverUnload;

    /* Registering the EX callback (blocking-capable) requires the driver to be
     * linked /INTEGRITYCHECK and properly signed, else STATUS_ACCESS_DENIED. */
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyEx, FALSE);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(g.Device);
        return status;
    }
    g.CallbackRegistered = TRUE;

    /* Tamper protection (W4a) — register the process-handle callback. Non-fatal:
     * if it fails, exec prevention still works; only self-protection is lost. */
    if (NT_SUCCESS(RegisterTamperCallback()))
        g.ObRegistered = TRUE;

    /* Injection telemetry (M2) — remote-thread creation callback. Non-fatal. */
    if (NT_SUCCESS(PsSetCreateThreadNotifyRoutine(ThreadNotify)))
        g.ThreadCbRegistered = TRUE;

    return STATUS_SUCCESS;
}
