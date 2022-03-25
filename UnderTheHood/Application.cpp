#include "Application.h"

Application* Application::s_application = nullptr;

Application::Application()
{
  // TODO: RE_ASSERT(s_application);
  s_application = this;
}

void Application::Run()
{
  while (isRunning)
  {
    // TODO: OnUpdate();
  }
}

void Application::OnEvent(const Event& acEvent)
{
  //if (acEvent.Type == Event::Type::CLOSE)
  {
    isRunning = false;
  }
}