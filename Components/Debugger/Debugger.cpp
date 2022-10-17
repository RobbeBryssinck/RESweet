#include "Debugger.h"

#include <Windows.h>

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

bool Debugger::IsDebugging() const
{
  // TODO: error handling
  auto handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
  BOOL isDebugging = false;
  CheckRemoteDebuggerPresent(handle, &isDebugging);
  return isDebugging;
}
