#include "Application.h"

#include <ImGuiImpl/imgui_runner.h>

#include <spdlog/spdlog.h>

Application* Application::s_application = nullptr;

Application::Application()
  : uiRunner("Under The Hood")
{
  RE_ASSERT(!s_application);
  s_application = this;

  dispatcher.Subscribe(Event::Type::kExit, std::bind(&Application::OnExit, this, std::placeholders::_1));
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
    if (!uiRunner.BeginFrame())
      break;

    for (Window* window : windows)
      window->Update();

    uiRunner.EndFrame();
  }
}

void Application::OnExit(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kExit);

  isRunning = false;
}