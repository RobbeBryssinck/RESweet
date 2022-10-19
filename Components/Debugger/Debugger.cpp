#include "Debugger.h"

#include <processthreadsapi.h>
#include <debugapi.h>
#include <chrono>

Debugger::Debugger()
  : debugThread(std::thread(&Debugger::DebugLoop, this))
{
}

bool Debugger::AttachDebugger(int aProcessID)
{
  // TODO: error handling
  BOOL result = DebugActiveProcess(aProcessID);

  if (result)
  {
    std::scoped_lock _(debugMtx);
    processID = aProcessID;
  }

  return result;
}

bool Debugger::StopDebugging()
{
  BOOL result = DebugActiveProcessStop(processID);

  {
    std::scoped_lock _(debugMtx);
    processID = 0;
  }

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

void Debugger::DebugLoop()
{
  DWORD continueStatus = DBG_CONTINUE;

  DEBUG_EVENT debugEvent{};

  while (true)
  {
    debugMtx.lock();
    if (!processID)
    {
      debugMtx.unlock();
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
      continue;
    }
    debugMtx.unlock();

    WaitForDebugEvent(&debugEvent, 500);

    switch (debugEvent.dwDebugEventCode)
    {
    case EXCEPTION_DEBUG_EVENT:
      switch (debugEvent.u.Exception.ExceptionRecord.ExceptionCode)
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
      continueStatus = OnCreateThreadDebugEvent(&debugEvent);
      break;

    case CREATE_PROCESS_DEBUG_EVENT:
      continueStatus = OnCreateProcessDebugEvent(&debugEvent);
      break;

    case EXIT_THREAD_DEBUG_EVENT:
      continueStatus = OnExitThreadDebugEvent(&debugEvent);
      break;

    case EXIT_PROCESS_DEBUG_EVENT:
      continueStatus = OnExitProcessDebugEvent(&debugEvent);
      break;

    case LOAD_DLL_DEBUG_EVENT:
      continueStatus = OnLoadDllDebugEvent(&debugEvent);
      break;

    case UNLOAD_DLL_DEBUG_EVENT:
      continueStatus = OnUnloadDllDebugEvent(&debugEvent);
      break;

    case OUTPUT_DEBUG_STRING_EVENT:
      continueStatus = OnOutputDebugStringEvent(&debugEvent);
      break;

    case RIP_EVENT:
      continueStatus = OnRipEvent(&debugEvent);
      break;
    }

    ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus);
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
