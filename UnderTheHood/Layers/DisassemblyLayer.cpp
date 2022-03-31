#include "DisassemblyLayer.h"
#include <imgui.h>

void DisassemblyLayer::Setup()
{
  count = 0;
}

void DisassemblyLayer::UpdateLogic()
{
  count += 1;
}

void DisassemblyLayer::UpdateUI()
{
  static bool show = false;
  ImGui::ShowDemoWindow(&show);
}

void DisassemblyLayer::OnEvent(const Event& acEvent)
{

}
