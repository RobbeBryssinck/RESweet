#include "Application.h"

#include <ImGuiImpl/imgui_runner.h>

Application* Application::s_application = nullptr;

Application::Application()
  : uiRunner("Under The Hood")
{
  // TODO: RE_ASSERT(s_application);
  s_application = this;
}

void Application::AddLayer(Layer* aLayer)
{
  layers.push_back(aLayer);
}

void Application::Run()
{
  while (isRunning)
  {
    for (Layer* layer : layers)
      layer->UpdateLogic();

    uiRunner.BeginFrame();
    for (Layer* layer : layers)
      layer->UpdateUI();
    uiRunner.EndFrame();
  }
}

void Application::OnEvent(const Event& acEvent)
{
  //if (acEvent.Type == Event::Type::CLOSE)
  {
    isRunning = false;
  }
}