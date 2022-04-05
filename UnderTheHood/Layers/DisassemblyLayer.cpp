#include "DisassemblyLayer.h"

#include <BinLoader/BaseParser.h>
#include <FileHandling.h>

#include <imgui.h>
#include <spdlog/spdlog.h>

#include <queue>
#include <set>

DisassemblyLayer::~DisassemblyLayer()
{
}

void DisassemblyLayer::Setup()
{
  count = 0;
}

void DisassemblyLayer::UpdateLogic()
{
  count += 1;

  if (shouldDisassemble)
  {
    std::shared_ptr<Binary> pBinary = Parsing::ParseFile(fileToDisassemble);
    functions = Disassembly::Disassemble(pBinary);

    shouldDisassemble = false;
  }
}

void DisassemblyLayer::UpdateUI()
{
  static bool show = false;
  ImGui::ShowDemoWindow(&show);

  ImGui::Begin("Disassembly");

  ImGui::Text("Count: %d", count);

  if (ImGui::Button("Disassemble"))
  {
    fileToDisassemble = OpenFileDialogue();
    shouldDisassemble = true;
  }

  if (!functions.empty())
  {
    ImGui::Text("Function count: %d", functions.size());

    static uint64_t address = 0;
    ImGui::InputScalar("Address", ImGuiDataType_U64, &address, 0, 0, "%" PRIx64, ImGuiInputTextFlags_CharsHexadecimal);
    if (ImGui::Button("Get function") && address)
    {
      auto functionIt = functions.find(address);
      if (functionIt == functions.end())
        spdlog::error("Function with address {:X} not found.", address);
      else
      {
        ImGui::OpenPopup(functionIt->second.name.c_str());
        modalFunction = functionIt->second;
      }
    }

    ImGui::Separator();

    for (const auto& function : functions)
    {
      if (ImGui::Button(function.second.name.c_str()))
      {
        ImGui::OpenPopup(function.second.name.c_str());
        modalFunction = function.second;
      }
    }
  }

  if (modalFunction)
    RenderDisassemblyModal(modalFunction);

  ImGui::End();
}

void DisassemblyLayer::RenderDisassemblyModal(const Disassembly::Function& acFunction)
{
  ImVec2 center = ImGui::GetMainViewport()->GetCenter();
  ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

  if (ImGui::BeginPopupModal(acFunction.name.c_str(), NULL, ImGuiWindowFlags_AlwaysAutoResize))
  {
    static std::string functionOutput = "";
    static uint64_t cachedAddress = 0;

    if (acFunction.address != cachedAddress)
    {
      cachedAddress = acFunction.address;
      functionOutput.clear();
      for (const cs_insn& instruction : acFunction.instructions)
        functionOutput += DisassemblyLayer::BuildInstructionString(&instruction);
    }

    static ImGuiInputTextFlags flags = ImGuiInputTextFlags_ReadOnly;
    ImGui::InputTextMultiline("##source", functionOutput.data(), functionOutput.size(), ImVec2(1000, 500), flags);

    if (ImGui::Button("Close"))
    {
        ImGui::CloseCurrentPopup();
        modalFunction = Disassembly::Function{};
    }

    ImGui::EndPopup();
  }
}

void DisassemblyLayer::OnEvent(const Event& acEvent)
{

}

std::string DisassemblyLayer::BuildInstructionString(const cs_insn* apInstruction)
{
  std::string instructionString = fmt::format("{:#018x}: ", apInstruction->address);

  for (size_t j = 0; j < 16; j++)
  {
    if (j < apInstruction->size)
      instructionString += fmt::format("{:02x} ", apInstruction->bytes[j]);
    else
      instructionString += "   ";
  }

  instructionString += fmt::format("{:<12}{}\n", apInstruction->mnemonic, apInstruction->op_str);

  return instructionString;
}
