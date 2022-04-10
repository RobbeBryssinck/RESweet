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
}

void StringsWindow::Update()
{
  ImGui::Begin("Strings");

  for (std::string& string : strings)
  {
    ImGui::PushTextWrapPos();
    ImGui::TextUnformatted(string.c_str());
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

void StringsWindow::Save() const
{
  SaveManager& saveManager = Application::Get().GetSaveManager();

  saveManager.resf.strings = strings;

  saveManager.isStringsReady = true;
}

void StringsWindow::Load()
{
  SaveManager& saveManager = Application::Get().GetSaveManager();

  strings = saveManager.resf.strings;
}
