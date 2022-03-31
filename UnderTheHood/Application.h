#pragma once

#include "Layers/Layer.h"

#include <ImGuiImpl/imgui_runner.h>

#include <vector>

// TODO: event system (or observer system?)
struct Event;

class Application
{
public:
  Application();

  [[nodiscard]] static Application& Get() { return *s_application; }

  void AddLayer(Layer* aLayer);

  void Run();
  void OnEvent(const Event& acEvent);
  
private:
  static Application* s_application;

  std::vector<Layer*> layers{};
  imgui_runner uiRunner{};

  bool isRunning = true;
};
