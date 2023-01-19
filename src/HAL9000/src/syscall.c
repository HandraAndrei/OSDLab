#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "thread.h"
#include "thread_internal.h"
#include "process_internal.h"
#include "dmp_cpu.h"

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
        // STUDENT TODO: implement the rest of the syscalls
        case SyscallIdFileWrite:
            status = SyscallFileWrite(
                (UM_HANDLE)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1],
                (QWORD)pSyscallParameters[2],
                (QWORD*)pSyscallParameters[3]
                );
            break;
        case SyscallIdThreadExit:
            status = SyscallThreadExit((STATUS)*pSyscallParameters);
            break;
        case SyscallIdProcessExit:
            status = SyscallProcessExit((STATUS)*pSyscallParameters);
            break;
            /*
        case SyscallIdThreadCreate:
            status = SyscallThreadCreate(
                (PFUNC_ThreadStart)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1],
                (UM_HANDLE*)pSyscallParameters[2]);
            break;
        case SyscallIdThreadGetTid:
            status = SyscallThreadGetTid(
                (UM_HANDLE)pSyscallParameters[0],
                (TID*)pSyscallParameters[1]);
            break;
        case SyscallIdThreadWaitForTermination:
            status = SyscallThreadWaitForTermination(
                (UM_HANDLE)pSyscallParameters[0],
                (STATUS*)pSyscallParameters[1]);
            break;
        case SyscallIdThreadCloseHandle:
            status = SyscallThreadCloseHandle(
                (UM_HANDLE)pSyscallParameters[0]);
            break;
        case SyscallIdProcessCreate:
            status = SyscallProcessCreate((char*)pSyscallParameters[0], (QWORD)pSyscallParameters[1], (char*)pSyscallParameters[2], (QWORD)pSyscallParameters[3], (UM_HANDLE*)pSyscallParameters[4]);
            break;
        case SyscallIdProcessCloseHandle:
            status = SyscallProcessCloseHandle((UM_HANDLE)pSyscallParameters[0]);
            break;
        case SyscallIdProcessGetPid:
            status = SyscallProcessGetPid((UM_HANDLE)pSyscallParameters[0], (PID*)pSyscallParameters[1]);
            break;
        case SyscallIdProcessWaitForTermination:
            status = SyscallProcessWaitForTermination((UM_HANDLE)pSyscallParameters[0], (STATUS*)pSyscallParameters[1]);
            break;
        case SyscallIdFileCreate:
            status = SyscallFileCreate((char*)pSyscallParameters[0], (QWORD)pSyscallParameters[1], (BOOLEAN)pSyscallParameters[2], (BOOLEAN)pSyscallParameters[3], (UM_HANDLE*)pSyscallParameters[4]);
            break;
        case SyscallIdFileRead:
            status = SyscallFileRead((UM_HANDLE)pSyscallParameters[0], (PVOID)pSyscallParameters[1], (QWORD)pSyscallParameters[2], (QWORD*)pSyscallParameters[3]);
            break;
        case SyscallIdFileClose:
            status = SyscallFileClose((UM_HANDLE)pSyscallParameters[0]);
            break;
            */
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
STATUS
SyscallFileWrite(
    IN  UM_HANDLE                   FileHandle,
    IN_READS_BYTES(BytesToWrite)
    PVOID                       Buffer,
    IN  QWORD                       BytesToWrite,
    OUT QWORD* BytesWritten
) 
{
    if (BytesWritten == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    if (FileHandle == UM_FILE_HANDLE_STDOUT) {
        *BytesWritten = BytesToWrite;
        LOG("[%s]:[%s]\n", ProcessGetName(NULL), Buffer);
        return STATUS_SUCCESS;
    }

    *BytesWritten = BytesToWrite;
    return STATUS_SUCCESS;


}
STATUS
SyscallThreadExit(
    IN STATUS   ExitStatus
)
{
    ThreadExit(ExitStatus);
    return STATUS_SUCCESS;
}
STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
    PPROCESS Process;
    Process = GetCurrentProcess();
    Process->TerminationStatus = ExitStatus;
    ProcessTerminate(Process);
    return STATUS_SUCCESS;
}

//threads from project
/*
STATUS
SyscallThreadCreate(
    IN      PFUNC_ThreadStart       StartFunction,
    IN_OPT  PVOID                   Context,
    OUT     UM_HANDLE* ThreadHandle
) {

    PTHREAD thread;

    if (StartFunction == NULL) {
        *ThreadHandle = UM_INVALID_HANDLE_VALUE;
        return STATUS_UNSUCCESSFUL;
    }


    STATUS validationStatus = MmuIsBufferValid((PVOID)StartFunction, sizeof(StartFunction), PAGE_RIGHTS_ALL, GetCurrentProcess());

    if (validationStatus != STATUS_SUCCESS) {
        *ThreadHandle = UM_INVALID_HANDLE_VALUE;
        return STATUS_UNSUCCESSFUL;
    }



    STATUS createStatus = ThreadCreateEx("name", ThreadPriorityDefault, StartFunction, Context, &thread, GetCurrentProcess());

    if (createStatus == STATUS_SUCCESS) {
        PPROCESS currentProcess = GetCurrentProcess();
        INTR_STATE dummyState;
        PHANDLE_THREAD structure = ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(HANDLE_THREAD), HEAP_HANDLE_TAG, 0);
        structure->Thread = thread;
        structure->Handle = handleGen;

        *ThreadHandle = handleGen;

        LockAcquire(&currentProcess->HandleListLock, &dummyState);
        handleGen++;
        InsertTailList(&currentProcess->HandleThreadList, &structure->HandleThreadList);
        LockRelease(&currentProcess->HandleListLock, dummyState);
    }

    return createStatus;
}
STATUS
SyscallThreadGetTid(
    IN_OPT  UM_HANDLE               ThreadHandle,
    OUT     TID* ThreadId
) {

    PPROCESS currentProcess = GetCurrentProcess();
    if (ThreadHandle == UM_INVALID_HANDLE_VALUE) {
        *ThreadId = GetCurrentThread()->Id;
        return STATUS_SUCCESS;
    }
    STATUS validationStatus = MmuIsBufferValid((PVOID)ThreadHandle, sizeof(ThreadHandle), PAGE_RIGHTS_ALL, GetCurrentProcess());

    if (validationStatus != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
    INTR_STATE dummyState;
    LockAcquire(&currentProcess->HandleListLock, &dummyState);
    PLIST_ENTRY handleEntryList = currentProcess->HandleThreadList.Flink;
    while (handleEntryList != &currentProcess->HandleThreadList) {
        PHANDLE_THREAD handleThread = CONTAINING_RECORD(handleEntryList, HANDLE_THREAD, HandleThreadList);
        if (handleThread->Handle == ThreadHandle) {
            *ThreadId = ThreadGetId(handleThread->Thread);
            LockRelease(&currentProcess->HandleListLock, dummyState);
            return STATUS_SUCCESS;
        }
        handleEntryList = handleEntryList->Flink;
    }
    LockRelease(&currentProcess->HandleListLock, dummyState);
    return STATUS_UNSUCCESSFUL;
}
STATUS
SyscallThreadWaitForTermination(
    IN      UM_HANDLE               ThreadHandle,
    OUT     STATUS* TerminationStatus
) {
    PPROCESS currentProcess = GetCurrentProcess();
    if (ThreadHandle == UM_INVALID_HANDLE_VALUE) {
        return STATUS_UNSUCCESSFUL;
    }

    STATUS validationStatus = MmuIsBufferValid((PVOID)ThreadHandle, sizeof(ThreadHandle), PAGE_RIGHTS_READ, GetCurrentProcess());

    if (validationStatus != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
    INTR_STATE dummyState;
    LockAcquire(&currentProcess->HandleListLock, &dummyState);
    PLIST_ENTRY handleEntryList = currentProcess->HandleThreadList.Flink;
    while (handleEntryList != &currentProcess->HandleThreadList) {
        PHANDLE_THREAD handleThread = CONTAINING_RECORD(handleEntryList, HANDLE_THREAD, HandleThreadList);
        if (handleThread->Handle == ThreadHandle) {
            ThreadWaitForTermination(handleThread->Thread, TerminationStatus);
            LockRelease(&currentProcess->HandleListLock, dummyState);
            return STATUS_SUCCESS;
        }
        handleEntryList = handleEntryList->Flink;
    }
    LockRelease(&currentProcess->HandleListLock, dummyState);
    return STATUS_UNSUCCESSFUL;
}

STATUS
SyscallThreadCloseHandle(
    IN      UM_HANDLE               ThreadHandle
) {
    PPROCESS currentProcess = GetCurrentProcess();
    if (ThreadHandle == UM_INVALID_HANDLE_VALUE) {
        return STATUS_UNSUCCESSFUL;
    }

    STATUS validationStatus = MmuIsBufferValid((PVOID)ThreadHandle, sizeof(ThreadHandle), PAGE_RIGHTS_ALL, GetCurrentProcess());
    if (validationStatus != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
    INTR_STATE dummyState;
    LockAcquire(&currentProcess->HandleListLock, &dummyState);
    PLIST_ENTRY handleEntryList = currentProcess->HandleThreadList.Flink;
    while (handleEntryList != &currentProcess->HandleThreadList) {
        PHANDLE_THREAD handleThread = CONTAINING_RECORD(handleEntryList, HANDLE_THREAD, HandleThreadList);
        if (handleThread->Handle == ThreadHandle) {
            ThreadCloseHandle(handleThread->Thread);
            //INTR_STATE dummyState;
            //LockAcquire(&currentProcess->HandleListLock, &dummyState);
            RemoveEntryList(&handleThread->HandleThreadList);
            LockRelease(&currentProcess->HandleListLock, dummyState);
            return STATUS_SUCCESS;
        }
        handleEntryList = handleEntryList->Flink;
    }
    LockRelease(&currentProcess->HandleListLock, dummyState);
    return STATUS_UNSUCCESSFUL;
}
*/

//from alex
/*
STATUS
SyscallProcessCreate(
    IN_READS_Z(PathLength)
    char* ProcessPath,
    IN          QWORD               PathLength,
    IN_READS_OPT_Z(ArgLength)
    char* Arguments,
    IN          QWORD               ArgLength,
    OUT         UM_HANDLE* ProcessHandle
)
{
    const char* Partition = IomuGetSystemPartitionPath();
    char app[14] = "Applications\\";
    char FinalPath[100];
    strncpy(FinalPath, Partition, strlen(Partition));
    strncpy(FinalPath + strlen(Partition), app, strlen(app));
    strncpy(FinalPath + strlen(Partition) + strlen(app), ProcessPath, strlen(ProcessPath));
    PPROCESS process = GetCurrentProcess();
    if (MmuIsBufferValid((PVOID)ProcessPath, PathLength, PAGE_RIGHTS_ALL, process) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    if (PathLength < 0) {

        return STATUS_SUCCESS;
    }
    if (ArgLength < 0) {

        return STATUS_SUCCESS;
    }
    PPROCESS createdProcess;
    STATUS status = ProcessCreate(FinalPath, Arguments, &createdProcess);
    if (status != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    PPROCESS_HANDLE handle = ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(PPROCESS_HANDLE), HEAP_HANDLE_TAG, 0);
    if (handle == NULL)
    {
        return STATUS_HEAP_INSUFFICIENT_RESOURCES;
    }
    handle->handle = globalHandle + 0x1;
    handle->process = createdProcess;
    INTR_STATE dummyState;
    if (process != NULL) {
        LockAcquire(&process->ProcessHandleLock, &dummyState);
        InsertHeadList(&process->ProcessHandleList, &handle->handleElem);
        LockRelease(&process->ProcessHandleLock, dummyState);
    }
    *ProcessHandle = handle->handle;
    globalHandle++;
    return STATUS_SUCCESS;
}

STATUS
SyscallProcessGetPid(
    IN_OPT  UM_HANDLE               ProcessHandle,
    OUT     PID* ProcessId
)
{

    if (ProcessHandle == UM_FILE_HANDLE_STDOUT || ProcessHandle == UM_INVALID_HANDLE_VALUE) {
        return STATUS_SUCCESS;
    }

    PPROCESS process = GetCurrentProcess();
    PLIST_ENTRY handleEntry = process->ProcessHandleList.Flink;
    INTR_STATE dummyState;
    LockAcquire(&process->ProcessHandleLock, &dummyState);
    while (handleEntry != &process->ProcessHandleList) {
        PROCESS_HANDLE* pHandle = CONTAINING_RECORD(handleEntry, PROCESS_HANDLE, handleElem);
        if (pHandle->handle == ProcessHandle) {
            *ProcessId = ProcessGetId(pHandle->process);
            return STATUS_SUCCESS;
        }
        handleEntry = handleEntry->Flink;
    }
    LockRelease(&process->ProcessHandleLock, dummyState);
    return STATUS_SUCCESS;
}

STATUS
SyscallProcessWaitForTermination(
    IN      UM_HANDLE               ProcessHandle,
    OUT     STATUS* TerminationStatus
)
{
    if (ProcessHandle == UM_FILE_HANDLE_STDOUT || ProcessHandle == UM_INVALID_HANDLE_VALUE) {
        return STATUS_SUCCESS;
    }

    PPROCESS process = GetCurrentProcess();
    PLIST_ENTRY handleEntry = process->ProcessHandleList.Flink;
    INTR_STATE dummyState;
    LockAcquire(&process->ProcessHandleLock, &dummyState);
    while (handleEntry != &process->ProcessHandleList) {
        PPROCESS_HANDLE pHandle = CONTAINING_RECORD(handleEntry, PROCESS_HANDLE, handleElem);

        if (pHandle->handle == ProcessHandle) {

            ProcessWaitForTermination(pHandle->process, TerminationStatus);
            LockRelease(&process->ProcessHandleLock, dummyState);
            return STATUS_SUCCESS;
        }
        handleEntry = handleEntry->Flink;
    }

    return STATUS_UNSUCCESSFUL;

}


STATUS
SyscallProcessCloseHandle(
    IN      UM_HANDLE               ProcessHandle
)
{
    PPROCESS process = GetCurrentProcess();
    if (ProcessHandle == UM_INVALID_HANDLE_VALUE) {
        return STATUS_SUCCESS;
    }

    if (ProcessHandle == UM_FILE_HANDLE_STDOUT) {
        return STATUS_INVALID_PARAMETER1;
    }

    PLIST_ENTRY handleEntry = process->ProcessHandleList.Flink;
    INTR_STATE dummyState;
    LockAcquire(&process->ProcessHandleLock, &dummyState);
    while (handleEntry != &process->ProcessHandleList) {
        PROCESS_HANDLE* pHandle = CONTAINING_RECORD(handleEntry, PROCESS_HANDLE, handleElem);
        if (pHandle->handle == ProcessHandle) {
            RemoveEntryList(handleEntry);
            ProcessCloseHandle(pHandle->process);
            LockRelease(&process->ProcessHandleLock, dummyState);
            return STATUS_SUCCESS;
        }
        handleEntry = handleEntry->Flink;
    }
    LockRelease(&process->ProcessHandleLock, dummyState);
    return STATUS_UNSUCCESSFUL;
}
STATUS
SyscallFileCreate(
    IN_READS_Z(PathLength)
    char* Path,
    IN          QWORD                   PathLength,
    IN          BOOLEAN                 Directory,
    IN          BOOLEAN                 Create,
    OUT         UM_HANDLE* FileHandle
)
{
    if (!Path) {
        return STATUS_UNSUCCESSFUL;
    }
    if (MmuIsBufferValid((PVOID)Path, PathLength, PAGE_RIGHTS_ALL, GetCurrentProcess()) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
    if (strlen(Path) == 0 || strcmp(Path, "") == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    const char* Partition = IomuGetSystemPartitionPath();
    char FinalPath[100];
    strncpy(FinalPath, Partition, strlen(Partition));
    strncpy(FinalPath + strlen(Partition), Path, strlen(Path));
    if (PathLength < 0) {
        return STATUS_UNSUCCESSFUL;
    }
    PPROCESS currentProcess = GetCurrentProcess();
    INTR_STATE dummyState;
    LockAcquire(&currentProcess->FileHandleLock, &dummyState);
    PLIST_ENTRY handleEntry = currentProcess->FileHandleList.Flink;
    while (handleEntry != &currentProcess->FileHandleList) {
        FILE_HANDLE* pHandle = CONTAINING_RECORD(handleEntry, FILE_HANDLE, handleElem);
        if (strcmp(pHandle->file->FileName, FinalPath) == 0) {
            LockRelease(&currentProcess->FileHandleLock, dummyState);
            return STATUS_UNSUCCESSFUL;
        }
        handleEntry = handleEntry->Flink;
    }
    LockRelease(&currentProcess->FileHandleLock, dummyState);
    PFILE_OBJECT file;
    IoCreateFile(&file, FinalPath, Directory, Create, FALSE);
    UM_HANDLE handleFile = globalHandle + 0x1;
    PFILE_HANDLE fileHandler = ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(PFILE_HANDLE), HEAP_HANDLE_TAG, 0);
    if (fileHandler == NULL)
    {
        return STATUS_HEAP_INSUFFICIENT_RESOURCES;
    }
    fileHandler->file = file;
    fileHandler->handle = handleFile;
    if (currentProcess != NULL) {
        LockAcquire(&currentProcess->FileHandleLock, &dummyState);
        InsertHeadList(&currentProcess->FileHandleList, &fileHandler->handleElem);
        LockRelease(&currentProcess->FileHandleLock, dummyState);
    }
    *FileHandle = fileHandler->handle;
    globalHandle++;

    return STATUS_SUCCESS;
}

STATUS
SyscallFileClose(
    IN          UM_HANDLE               FileHandle
)
{
    if (FileHandle == UM_INVALID_HANDLE_VALUE) {
        return STATUS_SUCCESS;
    }
    if (FileHandle == UM_FILE_HANDLE_STDOUT) {
        return STATUS_SUCCESS;
    }

    PPROCESS currentProcess = GetCurrentProcess();
    INTR_STATE dummyState;
    LockAcquire(&currentProcess->FileHandleLock, &dummyState);
    PLIST_ENTRY handleEntry = currentProcess->FileHandleList.Flink;
    while (handleEntry != &currentProcess->FileHandleList) {
        FILE_HANDLE* pHandle = CONTAINING_RECORD(handleEntry, FILE_HANDLE, handleElem);
        if (pHandle->handle == FileHandle) {

            RemoveEntryList(handleEntry);
            IoCloseFile(pHandle->file);
            LockRelease(&currentProcess->FileHandleLock, dummyState);
            return STATUS_SUCCESS;
        }
        handleEntry = handleEntry->Flink;
    }
    LockRelease(&currentProcess->FileHandleLock, dummyState);
    return STATUS_FILE_NOT_FOUND;
}

STATUS
SyscallFileRead(
    IN  UM_HANDLE                   FileHandle,
    OUT_WRITES_BYTES(BytesToRead)
    PVOID                       Buffer,
    IN  QWORD                       BytesToRead,
    OUT QWORD* BytesRead
)
{
    if (BytesToRead == 0) {
        *BytesRead = 0;
        return STATUS_SUCCESS;
    }
    PPROCESS currentProcess = GetCurrentProcess();
    if (MmuIsBufferValid(Buffer, BytesToRead, PAGE_RIGHTS_READ, currentProcess) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
    if (FileHandle == UM_FILE_HANDLE_STDOUT || FileHandle == UM_INVALID_HANDLE_VALUE) {
        return STATUS_FILE_NOT_FOUND;
    }



    INTR_STATE dummyState;
    LockAcquire(&currentProcess->FileHandleLock, &dummyState);
    PLIST_ENTRY handleEntry = currentProcess->FileHandleList.Flink;
    while (handleEntry != &currentProcess->FileHandleList) {
        FILE_HANDLE* pHandle = CONTAINING_RECORD(handleEntry, FILE_HANDLE, handleElem);
        if (pHandle->handle == FileHandle) {
            IoReadFile(pHandle->file, BytesToRead, 0, Buffer, BytesRead);
            if (BytesRead == NULL) {
                LockRelease(&currentProcess->FileHandleLock, dummyState);
                return STATUS_UNSUCCESSFUL;
            }
            LockRelease(&currentProcess->FileHandleLock, dummyState);
            return STATUS_SUCCESS;
        }
        handleEntry = handleEntry->Flink;
    }
    LockRelease(&currentProcess->FileHandleLock, dummyState);
    return STATUS_SUCCESS;
}
*/