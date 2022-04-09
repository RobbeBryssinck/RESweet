#include "MenuWindow.h"

#include "../Application.h"

#include <FileHandling.h>

#include <imgui.h>
#include <spdlog/spdlog.h>

void MenuWindow::Setup()
{
  Application::Get().GetDispatcher().Subscribe(EventType::kTest, std::bind(&MenuWindow::OnTestEvent, this, std::placeholders::_1));
}

void MenuWindow::Update()
{
  ImGui::Begin("Menu");

  if (ImGui::Button("Open file"))
    Application::Get().GetDispatcher().Dispatch(OpenFileEvent(OpenFileDialogue()));

  if (ImGui::Button("Dispatch test event"))
    Application::Get().GetDispatcher().Dispatch(TestEvent());

  ImGui::End();
}

void MenuWindow::OnTestEvent(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == EventType::kTest);

  spdlog::info("Test event");
}
