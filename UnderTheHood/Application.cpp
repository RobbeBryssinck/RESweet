#include "Application.h"

#include <ImGuiImpl/imgui_runner.h>

Application* Application::s_application = nullptr;

Application::Application()
  : uiRunner("Under The Hood")
{
  // TODO: RE_ASSERT(s_application);
  s_application = this;
}

void Application::AddWindow(Window* apWindow)
{
  windows.push_back(apWindow);
}

void Application::Run()
{
  while (isRunning)
  {
    for (Window* window : windows)
      window->UpdateLogic();

    uiRunner.BeginFrame();
    for (Window* window : windows)
      window->UpdateUI();
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