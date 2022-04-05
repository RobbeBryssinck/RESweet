#pragma once

#include <windows.h>
#include <WinUser.h>
#include <string>

class imgui_runner
{
public:
  imgui_runner(const std::string& acName);
  ~imgui_runner();

  void BeginFrame();
  void EndFrame();

private:
  HWND hwnd;
  WNDCLASSEX wc;
};
