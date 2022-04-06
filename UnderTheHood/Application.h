#pragma once

#include "Windows/Window.h"

#include <ImGuiImpl/imgui_runner.h>

#include <vector>

// TODO: event system (or observer system?)
struct Event;

class Application
{
public:
  Application();

  [[nodiscard]] static Application& Get() { return *s_application; }

  void AddWindow(Window* apWindow);

  void Run();
  void OnEvent(const Event& acEvent);
  
private:
  static Application* s_application;

  std::vector<Window*> windows{};
  imgui_runner uiRunner;

  bool isRunning = true;
};
