#pragma once

class Debugger
{
public:
  bool AttachDebugger(int aProcessID);

  int GetProcessID() const { return processID; }

private:
  int processID{0};
};
