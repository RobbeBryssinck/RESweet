#pragma once

#include "Windows/Window.h"
#include "SaveLoad/RESF.h"

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
  [[nodiscard]] SaveLoadManager& GetSaveLoadManager() { return saveLoadManager; }

  void AddWindow(Window* apWindow);

  void Run();

  void OnExit(const Event& aEvent);

  template <class T>
  void ToggleWindowShown()
  {
    for (auto* pWindow : windows)
    {
      if (dynamic_cast<T*>(pWindow))
        pWindow->ToggleWindowShown();
    }
  }

  template <class T>
  void ShowOrHideWindow(bool aShow)
  {
    for (auto* pWindow : windows)
    {
      if (dynamic_cast<T*>(pWindow))
        pWindow->SetShown(aShow);
    }
  }
  
private:
  static Application* s_application;

  std::vector<Window*> windows{};
  EventDispatcher dispatcher{};
  imgui_runner uiRunner;

  bool isRunning = true;

  SaveLoadManager saveLoadManager{};
};
