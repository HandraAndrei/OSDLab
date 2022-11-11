#include "HAL9000.h"
#include "ex_timer.h"
#include "iomu.h"
#include "thread_internal.h"


INT64
ExTimerCompareListElems(
    IN PLIST_ENTRY t1,
    IN PLIST_ENTRY t2,
    IN_OPT PVOID context
)
{
    ASSERT(NULL == context);
    EX_TIMER* timer1 = CONTAINING_RECORD(t1, EX_TIMER, TimerListEvent);
    EX_TIMER* timer2 = CONTAINING_RECORD(t2, EX_TIMER, TimerListEvent);

    if (ExTimerCompareTimers(timer1, timer2) > 0) {
        return 1;
    }
    if (ExTimerCompareTimers(timer1, timer2) == 0) {
        return 0;
    }

    return -1;
}

STATUS
ExTimerInit(
    OUT     PEX_TIMER       Timer,
    IN      EX_TIMER_TYPE   Type,
    IN      QWORD           Time
)
{
    STATUS status;

    if (NULL == Timer)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (Type > ExTimerTypeMax)
    {
        return STATUS_INVALID_PARAMETER2;
    }

    status = STATUS_SUCCESS;

    memzero(Timer, sizeof(EX_TIMER));

    Timer->Type = Type;
    if (Timer->Type != ExTimerTypeAbsolute)
    {
        // relative time

        // if the time trigger time has already passed the timer will
        // be signaled after the first scheduler tick
        Timer->TriggerTimeUs = IomuGetSystemTimeUs() + Time;
        Timer->ReloadTimeUs = Time;
    }
    else
    {
        // absolute
        Timer->TriggerTimeUs = Time;
    }

    INTR_STATE dummyState;

    ExEventInit(&Timer->TimerEvent, ExEventTypeNotification, FALSE);
    LockAcquire(&m_globalTimerList.TimerListLock, &dummyState);
    InsertOrderedList(&m_globalTimerList.TimerListHead, &Timer->TimerListEvent, ExTimerCompareListElems, NULL);
    LockRelease(&m_globalTimerList.TimerListLock, dummyState);

    return status;
}

void
ExTimerSystemPreinit(
    void
)
{
    InitializeListHead(&m_globalTimerList.TimerListHead);
    LockInit(&m_globalTimerList.TimerListLock);
}

STATUS
ExTimerCheck(
    IN PLIST_ENTRY Timer,
    IN_OPT PVOID context
)
{

    ASSERT(NULL == context);
    QWORD system_time = IomuGetSystemTimeUs();
    EX_TIMER* timer = CONTAINING_RECORD(Timer, EX_TIMER, TimerListEvent);
    if (system_time >= timer->TriggerTimeUs) {
        ExEventSignal(&timer->TimerEvent);
    }
    return STATUS_SUCCESS;
}

void
ExTimerCheckAll(
    void
)
{
    INTR_STATE dummyState;
    LockAcquire(&m_globalTimerList.TimerListLock, &dummyState);
    ForEachElementExecute(&m_globalTimerList.TimerListHead, (PFUNC_ListFunction)ExTimerCheck, NULL, FALSE);
    LockRelease(&m_globalTimerList.TimerListLock, dummyState);
}

void
ExTimerStart(
    IN      PEX_TIMER       Timer
)
{
    ASSERT(Timer != NULL);

    if (Timer->TimerUninited)
    {
        return;
    }

    Timer->TimerStarted = TRUE;
}

void
ExTimerStop(
    IN      PEX_TIMER       Timer
)
{
    ASSERT(Timer != NULL);

    if (Timer->TimerUninited)
    {
        return;
    }

    Timer->TimerStarted = FALSE;
    ExEventSignal(&Timer->TimerEvent);
}

void
ExTimerWait(
    INOUT   PEX_TIMER       Timer
)
{
    ASSERT(Timer != NULL);

    if (Timer->TimerUninited)
    {
        return;
    }

    /*while (IomuGetSystemTimeUs() < Timer->TriggerTimeUs && Timer->TimerStarted)
    {
        ThreadYield();
    }*/
    ExEventWaitForSignal(&Timer->TimerEvent);
}

void
ExTimerUninit(
    INOUT   PEX_TIMER       Timer
)
{
    ASSERT(Timer != NULL);

    ExTimerStop(Timer);

    Timer->TimerUninited = TRUE;

    INTR_STATE dummyState;
    LockAcquire(&m_globalTimerList.TimerListLock, &dummyState);
    RemoveEntryList(&Timer->TimerListEvent);
    LockRelease(&m_globalTimerList.TimerListLock, dummyState);
}

INT64
ExTimerCompareTimers(
    IN      PEX_TIMER     FirstElem,
    IN      PEX_TIMER     SecondElem
)
{
    return FirstElem->TriggerTimeUs - SecondElem->TriggerTimeUs;
}