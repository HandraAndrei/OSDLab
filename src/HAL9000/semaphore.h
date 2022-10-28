#pragma once

#include "list.h"
#include "synch.h"
#include "HAL9000.h"


typedef struct _SEMAPHORE
{
    DWORD           Value;
    LOCK            SemaphoreLock;

    _Guarded_by_(SemaphoreLock)
    LIST_ENTRY          WaitingList;
    // ... add more fields here ...
} SEMAPHORE, * PSEMAPHORE;

void
SemaphoreInit(
    OUT     PSEMAPHORE      Semaphore,
    IN      DWORD           InitialValue
);

void
SemaphoreDown(
    INOUT   PSEMAPHORE      Semaphore,
    IN      DWORD           Value
);

void
SemaphoreUp(
    INOUT   PSEMAPHORE      Semaphore,
    IN      DWORD           Value
);