#pragma once

#include "Windows/Window.h"

#include <ImGuiImpl/imgui_runner.h>

#include <vector>

#define RE_ASSERT(x) if (!(x)) \
  DebugBreak();

class Application
{
public:
  Application();

  [[nodiscard]] static Application& Get() { return *s_application; }

  [[nodiscard]] EventDispatcher& GetDispatcher() { return dispatcher; }

  void AddWindow(Window* apWindow);

  void Run();
  void OnEvent(const Event& acEvent);
  
private:
  static Application* s_application;

  std::vector<Window*> windows{};
  EventDispatcher dispatcher{};
  imgui_runner uiRunner;

  bool isRunning = true;
};
