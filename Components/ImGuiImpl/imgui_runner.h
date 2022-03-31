#pragma once

#include <windows.h>
#include <WinUser.h>

bool RunImGui();

class imgui_runner
{
public:
  imgui_runner();
  ~imgui_runner();

  void BeginFrame();
  void EndFrame();

private:
  HWND hwnd;
  WNDCLASSEX wc;
};
