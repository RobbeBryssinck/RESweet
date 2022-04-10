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
    const std::string filename = OpenFileDialogue(&dialogueTitle, &filters);

    SaveManager& saveManager = Application::Get().GetSaveManager();

    Reader reader{};
    if (!reader.LoadFromFile(filename))
      spdlog::error("Failed to load buffer from file.");

    saveManager.resf.Deserialize(reader);

    Application::Get().GetDispatcher().Dispatch(LoadEvent());
  }

  ImGui::Separator();

  if (ImGui::Button("Save"))
  {
    Application::Get().GetDispatcher().Dispatch(SaveEvent());

    SaveManager& saveManager = Application::Get().GetSaveManager();
    bool saveResult = saveManager.Save();
    spdlog::info("Save succeeded? {}", saveResult);
  }

  if (ImGui::Button("Dispatch test event"))
    Application::Get().GetDispatcher().Dispatch(TestEvent());

  ImGui::End();
}

void MenuWindow::OnTestEvent(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kTest);

  spdlog::info("Test event");
}
