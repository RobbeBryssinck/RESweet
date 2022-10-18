#pragma once

#include <Windows.h>

class Debugger
{
public:
  bool AttachDebugger(int aProcessID);
  bool StopDebugging();
  void DebugLoop(const LPDEBUG_EVENT aDebugEvent);

  int GetProcessID() const { return processID; }
  bool IsDebugging() const;

private:
  int processID{0};
};
