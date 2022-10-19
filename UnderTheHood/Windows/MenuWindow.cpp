#include "MenuWindow.h"

#include "../Application.h"
#include "AttacherWindow.h"

#include <FileHandling.h>

#include <imgui.h>
#include <spdlog/spdlog.h>

void MenuWindow::Setup()
{
  Application::Get().GetDispatcher().Subscribe(Event::Type::kTest, std::bind(&MenuWindow::OnTestEvent, this, std::placeholders::_1));
}

void MenuWindow::Update()
{
  static bool s_imguiDemo = false;

  ImGui::BeginMainMenuBar();

  if (ImGui::BeginMenu("Files"))
  {
    if (ImGui::Button("Open new file"))
    {
      openedFile = OpenFileDialogue();
      Application::Get().GetDispatcher().Dispatch(OpenFileEvent(openedFile));
    }

    if (ImGui::Button("Load"))
    {
      FileFilters filters{ {"RESweet save file", "*.resf"} };
      const std::string dialogueTitle = "Open RESweet save file";
      const std::string filename = OpenFileDialogue(&dialogueTitle, &filters);

      SaveLoadManager& saveLoadManager = Application::Get().GetSaveLoadManager();

      Reader reader{};
      if (!reader.LoadFromFile(filename))
        spdlog::error("Failed to load buffer from file.");
      else
      {
        saveLoadManager.resf.Deserialize(reader);

        openedFile = saveLoadManager.resf.header.filename;

        Application::Get().GetDispatcher().Dispatch(LoadEvent());
      }
    }

    if (ImGui::Button("Save"))
    {
      Application::Get().GetDispatcher().Dispatch(SaveEvent());

      SaveLoadManager& saveLoadManager = Application::Get().GetSaveLoadManager();

      saveLoadManager.resf.header.filename = openedFile;
      saveLoadManager.SetFilePath(openedFile);

      bool saveResult = saveLoadManager.Save();
      spdlog::info("Save succeeded? {}", saveResult);
    }

    if (ImGui::Button("Close session"))
    {
      openedFile = "";
      Application::Get().GetDispatcher().Dispatch(CloseEvent());
    }

    if (ImGui::Button("Exit"))
      Application::Get().GetDispatcher().Dispatch(ExitEvent());

    ImGui::EndMenu();
  }

  if (ImGui::BeginMenu("Views"))
  {
    ImGui::Checkbox("ImGui demo", &s_imguiDemo);

    ImGui::EndMenu();
  }

  if (ImGui::BeginMenu("Debugging"))
  {
    if (ImGui::Button("Attach to process..."))
      Application::Get().ToggleWindowShown<AttacherWindow>();

    if (ImGui::Button("Test"))
      Application::Get().GetDispatcher().Enqueue(TestEvent());

    ImGui::EndMenu();
  }

  ImGui::EndMainMenuBar();

  if (s_imguiDemo)
    ImGui::ShowDemoWindow(&s_imguiDemo);
}

void MenuWindow::OnTestEvent(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kTest);

  spdlog::info("Test event");
}
