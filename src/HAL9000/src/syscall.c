#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "thread.h"
#include "thread_internal.h"

extern void SyscallEntry();

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION

void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE    *CompleteProcessorState
    )
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

        // Dispatch syscalls
        switch (sysCallId)
        {
        case SyscallIdIdentifyVersion:
            status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
            break;
         //STUDENT TODO: implement the rest of the syscalls
        //case SyscallIdThreadExit:
        //    status = SyscallThreadExit((DWORD)pSyscallParameters[0]);
        //    break;
        //case SyscallIdThreadCreate:
        //    status = SyscallThreadCreate((PFUNC_ThreadStart)pSyscallParameters[0], (PVOID)pSyscallParameters[1], (UM_HANDLE*)pSyscallParameters[2]);
        //    break;
        //case SyscallIdThreadGetTid:
        //    status = SyscallThreadGetTid((UM_HANDLE)pSyscallParameters[0], (TID *)pSyscallParameters[1]);
        //    break;
        //case SyscallIdThreadWaitForTermination:
        //    status = SyscallThreadWaitForTermination((UM_HANDLE)pSyscallParameters[0], (STATUS*)pSyscallParameters[1]);
        //    break;
        //case SyscallIdThreadCloseHandle:
        //    status = SyscallThreadCloseHandle((UM_HANDLE)pSyscallParameters[0]);
        //    break;
        //case SyscallIdFileWrite:
        //    status = SyscallFileWrite((UM_HANDLE)pSyscallParameters[0], (PVOID)pSyscallParameters[1], (QWORD)pSyscallParameters[2], (QWORD*)pSyscallParameters[3]);
        //    break;
        default:
            LOG_ERROR("Unimplemented syscall called from User-space!\n");
            status = STATUS_UNSUPPORTED;
            break;
        }

    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
    )
{

}

STATUS
SyscallInitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
    )
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD) SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD) SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}

// STUDENT TODO: implement the rest of the syscalls

//typedef enum _UM_HANDLE_DATA_TYPES {
//
//    FileHandle,
//    ProcessHandle,
//    ThreadHandle,
//    
//    // Not an actual value, just for getting the size of this enum
//    // Please keep it as the last entry
//    _TotalHandleTypes
//} UM_HANDLE_TYPE;
//
//#define HANDLE_MAP_MAX_ENTRIES      1000 * _TotalHandleTypes
//PVOID HandleMap[HANDLE_MAP_MAX_ENTRIES];
//
//// Handle manager
//
//STATUS
//UMInitialize
//(
//    void
//)
//{
//    for (int i = 0; i < HANDLE_MAP_MAX_ENTRIES; i++) {
//        HandleMap[i] = NULL;
//    }
//
//    return STATUS_SUCCESS;
//}
//
//STATUS
//UMCreate(
//    IN      UM_HANDLE_TYPE          HandleType,
//    IN      PVOID                   p,
//    OUT     UM_HANDLE*              handle
//)
//{
//    ASSERT(HandleType >= 0);
//    ASSERT(HandleType < _TotalHandleTypes);
//
//    UM_HANDLE i = HandleType;
//
//    while (i < HANDLE_MAP_MAX_ENTRIES && HandleMap[i] != NULL)
//    {
//        i += _TotalHandleTypes;
//    }
//
//    if (i >= HANDLE_MAP_MAX_ENTRIES)
//        // Placeholder, send status for filled table
//        return STATUS_INVALID_POINTER;
//
//    HandleMap[i] = p;
//    *handle = i + 1;
//
//    return STATUS_SUCCESS;
//}
//
//STATUS
//UMCreateThread(
//    IN      PTHREAD                 pThread,
//    OUT     UM_HANDLE*              handle
//)
//{
//    return UMCreate(ThreadHandle, (PVOID)pThread, handle);
//}
//
//STATUS
//UMGet(
//    IN      UM_HANDLE_TYPE          HandleType,
//    IN      UM_HANDLE               handle,
//    OUT     PVOID*                  p
//)
//{
//
//    ASSERT(HandleType >= 0);
//    ASSERT(HandleType < _TotalHandleTypes);
//
//    if ((handle - 1) % _TotalHandleTypes != HandleType || (handle - 1) >= HANDLE_MAP_MAX_ENTRIES || (handle - 1) < 0)
//        // Placeholder, invalid handle
//        return STATUS_INVALID_POINTER;
//
//    if (HandleMap[(handle - 1)] == NULL)
//        // Placeholder, handle is either not created or closed
//        return STATUS_INVALID_POINTER;
//
//    *p = HandleMap[(handle - 1)];
//
//    return STATUS_SUCCESS;
//}
//
//STATUS 
//UMGetThread(
//    IN      UM_HANDLE               handle,
//    OUT     PTHREAD*                pThread
//)
//{
//    PVOID p = NULL;
//    STATUS status;
//
//    status = UMGet(ThreadHandle, handle, p);
//    
//    *pThread = (PTHREAD)p;
//    return status;
//}
//
//STATUS
//UMCloseHandle(
//    IN      UM_HANDLE_TYPE          HandleType,
//    IN      UM_HANDLE               handle
//)
//{
//    ASSERT(HandleType >= 0);
//    ASSERT(HandleType < _TotalHandleTypes);
//
//    if ((handle - 1) % _TotalHandleTypes != HandleType || (handle - 1) >= HANDLE_MAP_MAX_ENTRIES || (handle - 1) < 0)
//        // Placeholder, invalid handle
//        return STATUS_INVALID_POINTER;
//
//    if (HandleMap[(handle - 1)] == NULL)
//        // Placeholder, handle is either not created or closed
//        return STATUS_INVALID_POINTER;
//
//    HandleMap[(handle - 1)] = NULL;
//
//    return STATUS_SUCCESS;
//}
//
//STATUS
//UMCloseThreadHandle(
//    IN      UM_HANDLE               handle
//)
//{
//    return UMCloseHandle(ThreadHandle, handle);
//}
//
//STATUS
//SyscallThreadCreate(
//    IN      PFUNC_ThreadStart       StartFunction,
//    IN_OPT  PVOID                   Context,
//    OUT     UM_HANDLE*              ThreadHandle
//)
//{
//    PTHREAD pThread = (PTHREAD)ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(THREAD), HEAP_THREAD_TAG, 0);
//    STATUS status;
//
//    status = MmuIsBufferValid((PVOID)ThreadHandle, sizeof(ThreadHandle), PAGE_RIGHTS_WRITE, GetCurrentProcess());
//    if (status != STATUS_SUCCESS) {
//        return STATUS_INVALID_POINTER;
//    }
//
//    status = ThreadCreate("SomeName", ThreadPriorityDefault, StartFunction, Context, &pThread);
//    if (status != STATUS_SUCCESS) {
//        return status;
//    }
//
//    status = UMCreateThread(pThread, ThreadHandle);
//
//    return status;
//}
//
//STATUS
//SyscallThreadExit(
//    IN      STATUS                  ExitStatus
//)
//{
//    ThreadExit(ExitStatus);
//
//    return STATUS_SUCCESS;
//}
//
//STATUS
//SyscallThreadGetTid(
//    IN_OPT  UM_HANDLE               ThreadHandle,
//    OUT     TID*                    ThreadId
//)
//{
//    PTHREAD pThread = NULL;
//    STATUS status;
//
//    status = MmuIsBufferValid((PVOID)ThreadId, sizeof(ThreadId), PAGE_RIGHTS_WRITE, GetCurrentProcess());
//    if (status != STATUS_SUCCESS) {
//        return STATUS_INVALID_POINTER;
//    }
//
//    if (ThreadHandle == UM_INVALID_HANDLE_VALUE)
//        pThread = GetCurrentThread();
//    else {
//        status = UMGetThread(ThreadHandle, &pThread);
//        if (status != STATUS_SUCCESS)
//            return status;
//    }
//
//    *ThreadId = ThreadGetId(pThread);
//
//    // This might not be needed, otherwise the error status is subject to change
//    return (ThreadId != 0) ? STATUS_SUCCESS : STATUS_INVALID_POINTER;
//}
//
//STATUS
//SyscallThreadWaitForTermination(
//    IN      UM_HANDLE               ThreadHandle,
//    OUT     STATUS*                 TerminationStatus
//)
//{
//    PTHREAD pThread = NULL;
//    STATUS status;
//
//    status = UMGetThread(ThreadHandle, &pThread);
//    if (status != STATUS_SUCCESS) {
//        return status;
//    }
//
//    status = MmuIsBufferValid((PVOID)TerminationStatus, sizeof(TerminationStatus), PAGE_RIGHTS_WRITE, GetCurrentProcess());
//    if (status != STATUS_SUCCESS) {
//        return STATUS_INVALID_POINTER;
//    }
//
//    ThreadWaitForTermination(pThread, TerminationStatus);
//
//    return STATUS_SUCCESS;
//}
//
//STATUS
//SyscallThreadCloseHandle(
//    IN      UM_HANDLE               ThreadHandle
//)
//{
//    return UMCloseThreadHandle(ThreadHandle);
//}

STATUS
SyscallFileWrite(
    IN  UM_HANDLE                   FileHandle,
    IN_READS_BYTES(BytesToWrite)
    PVOID                           Buffer,
    IN  QWORD                       BytesToWrite,
    OUT QWORD*                      BytesWritten
)
{
    if (FileHandle != FileHandle)
        return STATUS_INVALID_POINTER;

    if (Buffer != NULL)
        *BytesWritten = BytesToWrite;

    LOG("[%s]:[%s]\n", ProcessGetName(NULL), Buffer);

    return STATUS_SUCCESS;
}
