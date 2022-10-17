#pragma once

class Debugger
{
public:
  bool AttachDebugger(int aProcessID);
  bool StopDebugging();

  int GetProcessID() const { return processID; }
  bool IsDebugging() const;

private:
  int processID{0};
};
