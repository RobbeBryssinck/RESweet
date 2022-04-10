#include "Application.h"

#include <ImGuiImpl/imgui_runner.h>

#include <spdlog/spdlog.h>

Application* Application::s_application = nullptr;

Application::Application()
  : uiRunner("Under The Hood")
{
  RE_ASSERT(!s_application);
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

  while (true)
  {
    if (!uiRunner.BeginFrame())
      break;

    for (Window* window : windows)
      window->Update();

    uiRunner.EndFrame();
  }
}