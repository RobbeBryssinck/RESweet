#include "StringsLayer.h"

#include <Strings/Strings.h>
#include <FileHandling.h>

#include <imgui.h>
#include <spdlog/spdlog.h>

void StringsLayer::Setup()
{
}

void StringsLayer::UpdateLogic()
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

void StringsLayer::UpdateUI()
{
  ImGui::Begin("Strings");

  if (ImGui::Button("Get strings"))
  {
    stringsFilename = OpenFileDialogue();
    shouldCollectStrings = true;
  }

  ImGui::End();
}

void StringsLayer::OnEvent(const Event& acEvent)
{
}
