#include "StringsWindow.h"

#include "../Application.h"

#include <Strings/Strings.h>
#include <FileHandling.h>

#include <imgui.h>
#include <spdlog/spdlog.h>

void StringsWindow::Setup()
{
  Application::Get().GetDispatcher().Subscribe(EventType::kOpenFile, std::bind(&StringsWindow::OnOpenFile, this, std::placeholders::_1));
}

void StringsWindow::Update()
{
  ImGui::Begin("Strings");

  if (ImGui::Button("Get strings"))
  {
    strings = Strings::GetStringsFromFile(OpenFileDialogue());

    for (std::string& string : strings)
      spdlog::debug(string);
  }

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
  RE_ASSERT(aEvent.GetType() == EventType::kOpenFile);

  const OpenFileEvent& fileEvent = static_cast<const OpenFileEvent&>(aEvent);

  strings = Strings::GetStringsFromFile(fileEvent.filename);
}
