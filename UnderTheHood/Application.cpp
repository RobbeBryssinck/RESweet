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
  for (Window* window : windows)
    window->Setup();

  while (isRunning)
  {
    uiRunner.BeginFrame();

    for (Window* window : windows)
      window->Update();

    uiRunner.EndFrame();
  }
}

void Application::OnEvent(const Event& acEvent)
{
  //if (acEvent.Type == Event::Type::CLOSE)
  if (0)
  {
    isRunning = false;
  }
}