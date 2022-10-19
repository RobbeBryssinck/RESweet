#pragma once

#include <Windows.h>
#include <thread>
#include <mutex>

class Debugger
{
public:
  Debugger();

  bool AttachDebugger(int aProcessID);
  bool StopDebugging();
  void DebugLoop();

  int GetProcessID() const { return processID; }
  bool IsDebugging() const;

private:
  int processID{0};
  std::mutex debugMtx{};
  std::thread debugThread{};
};
