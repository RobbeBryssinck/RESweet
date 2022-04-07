#pragma once

#include <windows.h>
#include <WinUser.h>
#include <string>

class imgui_runner
{
public:
  imgui_runner(const std::string& acName);
  ~imgui_runner();
  imgui_runner(const imgui_runner&) = default;
  imgui_runner& operator=(const imgui_runner&) = default;

  void BeginFrame();
  void EndFrame();

private:
  HWND hwnd;
  WNDCLASSEX wc;
};
