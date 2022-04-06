#include "StringsWindow.h"

#include <Strings/Strings.h>
#include <FileHandling.h>

#include <imgui.h>
#include <spdlog/spdlog.h>

void StringsWindow::Setup()
{
}

void StringsWindow::UpdateLogic()
{
  if (shouldCollectStrings)
  {
    if (strings.size() == 0)
      strings = Strings::GetStringsFromFile(stringsFilename);

    shouldCollectStrings = false;

    for (std::string& string : strings)
      spdlog::info(string);
  }
}

void StringsWindow::UpdateUI()
{
  ImGui::Begin("Strings");

  if (ImGui::Button("Get strings"))
  {
    stringsFilename = OpenFileDialogue();
    shouldCollectStrings = true;
  }

  ImGui::End();
}

void StringsWindow::OnEvent(const Event& acEvent)
{
}
