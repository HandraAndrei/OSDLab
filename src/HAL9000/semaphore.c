#include "HAL9000.h"
#include "thread_internal.h"
#include "semaphore.h"

void
SemaphoreInit(
    OUT     PSEMAPHORE      Semaphore,
    IN      DWORD           InitialValue
) {
    ASSERT(NULL != Semaphore);

    memzero(Semaphore, sizeof(SEMAPHORE));

    LockInit(&Semaphore->SemaphoreLock);

    InitializeListHead(&Semaphore->WaitingList);

    Semaphore->Value = InitialValue;

}

void
SemaphoreDown(
    INOUT   PSEMAPHORE      Semaphore,
    IN      DWORD           Value
) {
    INTR_STATE dummystate;
    INTR_STATE oldState;
    PTHREAD pCurrentThread = GetCurrentThread();

    ASSERT(NULL != Semaphore);
    ASSERT(NULL != pCurrentThread);

    oldState = CpuIntrDisable();

    LockAcquire(&Semaphore->SemaphoreLock, &dummystate);
    
    while (Semaphore->Value - Value < 0) {
        InsertTailList(&Semaphore->WaitingList, &pCurrentThread->ReadyList);
        ThreadTakeBlockLock();
        LockRelease(&Semaphore->SemaphoreLock, dummystate);
        ThreadBlock();
        LockAcquire(&Semaphore->SemaphoreLock, &dummystate);
    }
    
    Semaphore->Value = Semaphore->Value - Value;
    LockRelease(&Semaphore->SemaphoreLock, dummystate);

    CpuIntrSetState(oldState);
    
}

void
SemaphoreUp(
    INOUT   PSEMAPHORE      Semaphore,
    IN      DWORD           Value
) {

    INTR_STATE oldState;
    PLIST_ENTRY pEntry = NULL;

    ASSERT(NULL != Semaphore);

    LockAcquire(&Semaphore->SemaphoreLock, &oldState);

    Semaphore->Value += Value;

    pEntry = RemoveHeadList(&Semaphore->WaitingList);
    if (pEntry != &Semaphore->WaitingList)
    {
        PTHREAD pThread = CONTAINING_RECORD(pEntry, THREAD, ReadyList);
        ThreadUnblock(pThread);
    }

    LockRelease(&Semaphore->SemaphoreLock, oldState);

}