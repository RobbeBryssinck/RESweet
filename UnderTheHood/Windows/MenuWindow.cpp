#include "MenuWindow.h"

#include "../Application.h"

#include <FileHandling.h>

#include <imgui.h>
#include <spdlog/spdlog.h>

void MenuWindow::Setup()
{
  Application::Get().GetDispatcher().Subscribe(Event::Type::kTest, std::bind(&MenuWindow::OnTestEvent, this, std::placeholders::_1));
}

void MenuWindow::Update()
{
  ImGui::Begin("Menu");

  if (ImGui::Button("Open file"))
    Application::Get().GetDispatcher().Dispatch(OpenFileEvent(OpenFileDialogue()));

  ImGui::SameLine();

  if (ImGui::Button("Load file"))
  {
    FileFilters filters{ {"RESweet save file", "*.resf"} };
    const std::string dialogueTitle = "Open RESweet save file";
    Application::Get().GetDispatcher().Dispatch(LoadEvent(OpenFileDialogue(&dialogueTitle, &filters)));
  }

  ImGui::Separator();

  if (ImGui::Button("Dispatch test event"))
    Application::Get().GetDispatcher().Dispatch(TestEvent());

  ImGui::End();
}

void MenuWindow::OnTestEvent(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kTest);

  spdlog::info("Test event");
}
