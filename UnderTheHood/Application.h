#pragma once

#include "Windows/Window.h"
#include "SaveLoad/RESF.h"

#include <ImGuiImpl/imgui_runner.h>

#include <vector>

#ifdef _WIN32
#define RE_ASSERT(x) if (!(x)) \
  DebugBreak();
#else
#define RE_ASSERT(x) (x)
#endif

class Application
{
public:
  Application();

  [[nodiscard]] static Application& Get() { return *s_application; }

  [[nodiscard]] EventDispatcher& GetDispatcher() { return dispatcher; }
  [[nodiscard]] SaveManager& GetSaveManager() { return saveManager; }

  void AddWindow(Window* apWindow);

  void Run();

  void OnExit(const Event& aEvent);
  
private:
  static Application* s_application;

  std::vector<Window*> windows{};
  EventDispatcher dispatcher{};
  imgui_runner uiRunner;

  bool isRunning = true;

  SaveManager saveManager{};
};
