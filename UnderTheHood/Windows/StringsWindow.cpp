#include "StringsWindow.h"

#include "../Application.h"

#include <Strings/Strings.h>
#include <FileHandling.h>

#include <imgui.h>
#include <spdlog/spdlog.h>

void StringsWindow::Setup()
{
  Application::Get().GetDispatcher().Subscribe(Event::Type::kOpenFile, std::bind(&StringsWindow::OnOpenFile, this, std::placeholders::_1));
  Application::Get().GetDispatcher().Subscribe(Event::Type::kLoad, std::bind(&StringsWindow::OnLoad, this, std::placeholders::_1));
  Application::Get().GetDispatcher().Subscribe(Event::Type::kSave, std::bind(&StringsWindow::OnSave, this, std::placeholders::_1));
  Application::Get().GetDispatcher().Subscribe(Event::Type::kClose, std::bind(&StringsWindow::OnClose, this, std::placeholders::_1));
}

void StringsWindow::Update()
{
  if (!IsLoaded())
    return;

  ImGui::Begin("Strings");

  for (std::string& string : strings)
  {
    ImGui::PushTextWrapPos();

    ImGui::TextUnformatted(string.c_str());
    if (ImGui::BeginPopupContextItem(string.c_str()))
    {
      if (ImGui::Selectable("Copy string"))
      {
        ImGui::LogToClipboard();
        ImGui::LogText(string.c_str());
        ImGui::LogFinish();
      }

      ImGui::EndPopup();
    }

    ImGui::PopTextWrapPos();

    ImGui::Separator();
  }

  ImGui::End();
}

void StringsWindow::OnOpenFile(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kOpenFile);

  const OpenFileEvent& fileEvent = static_cast<const OpenFileEvent&>(aEvent);

  strings = Strings::GetStringsFromFile(fileEvent.filename);
}

void StringsWindow::OnLoad(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kLoad);

  Load();
}

void StringsWindow::OnSave(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kSave);

  Save();
}

void StringsWindow::OnClose(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kClose);

  Destroy();
}

void StringsWindow::Save() const
{
  SaveLoadManager& saveLoadManager = Application::Get().GetSaveLoadManager();

  saveLoadManager.resf.strings = strings;

  saveLoadManager.isStringsReady = true;
}

void StringsWindow::Load()
{
  SaveLoadManager& saveLoadManager = Application::Get().GetSaveLoadManager();

  strings = saveLoadManager.resf.strings;
}

void StringsWindow::Destroy()
{
  strings.clear();
}
