#include "StringsWindow.h"

#include <Strings/Strings.h>
#include <FileHandling.h>

#include <imgui.h>
#include <spdlog/spdlog.h>

void StringsWindow::Setup()
{
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

void StringsWindow::OnEvent(const Event& acEvent)
{
}