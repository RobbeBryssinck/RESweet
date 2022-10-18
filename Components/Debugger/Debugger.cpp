#include "Debugger.h"

#include <processthreadsapi.h>
#include <debugapi.h>

bool Debugger::AttachDebugger(int aProcessID)
{
  processID = aProcessID;

  return DebugActiveProcess(processID);
}

bool Debugger::StopDebugging()
{
  BOOL result = DebugActiveProcessStop(processID);
  processID = 0;
  return result;
}

DWORD OnCreateThreadDebugEvent(const LPDEBUG_EVENT)
{
  return DBG_CONTINUE;
}

DWORD OnCreateProcessDebugEvent(const LPDEBUG_EVENT)
{
  return DBG_CONTINUE;
}

DWORD OnExitThreadDebugEvent(const LPDEBUG_EVENT)
{
  return DBG_CONTINUE;
}

DWORD OnExitProcessDebugEvent(const LPDEBUG_EVENT)
{
  return DBG_CONTINUE;
}

DWORD OnLoadDllDebugEvent(const LPDEBUG_EVENT)
{
  return DBG_CONTINUE;
}

DWORD OnUnloadDllDebugEvent(const LPDEBUG_EVENT)
{
  return DBG_CONTINUE;
}

DWORD OnOutputDebugStringEvent(const LPDEBUG_EVENT)
{
  return DBG_CONTINUE;
}

DWORD OnRipEvent(const LPDEBUG_EVENT)
{
  return DBG_CONTINUE;
}

void Debugger::DebugLoop(const LPDEBUG_EVENT aDebugEvent)
{
  DWORD continueStatus = DBG_CONTINUE;

  while (true)
  {
    WaitForDebugEvent(aDebugEvent, INFINITE);

    switch (aDebugEvent->dwDebugEventCode)
    {
    case EXCEPTION_DEBUG_EVENT:
      switch (aDebugEvent->u.Exception.ExceptionRecord.ExceptionCode)
      {
      case EXCEPTION_ACCESS_VIOLATION:
        break;
      case EXCEPTION_BREAKPOINT:
        break;
      case EXCEPTION_DATATYPE_MISALIGNMENT:
        break;
      case EXCEPTION_SINGLE_STEP:
        break;
      case DBG_CONTROL_C:
        break;
      default:
        break;
      }

      break;

    case CREATE_THREAD_DEBUG_EVENT:
      continueStatus = OnCreateThreadDebugEvent(aDebugEvent);
      break;

    case CREATE_PROCESS_DEBUG_EVENT:
      continueStatus = OnCreateProcessDebugEvent(aDebugEvent);
      break;

    case EXIT_THREAD_DEBUG_EVENT:
      continueStatus = OnExitThreadDebugEvent(aDebugEvent);
      break;

    case EXIT_PROCESS_DEBUG_EVENT:
      continueStatus = OnExitProcessDebugEvent(aDebugEvent);
      break;

    case LOAD_DLL_DEBUG_EVENT:
      continueStatus = OnLoadDllDebugEvent(aDebugEvent);
      break;

    case UNLOAD_DLL_DEBUG_EVENT:
      continueStatus = OnUnloadDllDebugEvent(aDebugEvent);
      break;

    case OUTPUT_DEBUG_STRING_EVENT:
      continueStatus = OnOutputDebugStringEvent(aDebugEvent);
      break;

    case RIP_EVENT:
      continueStatus = OnRipEvent(aDebugEvent);
      break;
    }

    ContinueDebugEvent(aDebugEvent->dwProcessId, aDebugEvent->dwThreadId, continueStatus);
  }
}

bool Debugger::IsDebugging() const
{
  // TODO: error handling
  auto handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
  BOOL isDebugging = false;
  CheckRemoteDebuggerPresent(handle, &isDebugging);
  return isDebugging;
}
