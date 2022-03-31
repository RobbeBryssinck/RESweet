#include "DisassemblyLayer.h"

#include <BinLoader/BaseParser.h>

#include <imgui.h>
#include <capstone/capstone.h>
#include <spdlog/spdlog.h>

DisassemblyLayer::~DisassemblyLayer()
{
  capstoneOutput.Destroy();
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
    capstoneOutput.Destroy();

    std::shared_ptr<Binary> pBinary = Parsing::ParseFile(std::move(fileToDisassemble));
    capstoneOutput.DisassembleLinear(pBinary);

    shouldDisassemble = false;
  }
}

void DisassemblyLayer::UpdateUI()
{
  static bool show = false;
  ImGui::ShowDemoWindow(&show);

  ImGui::Begin("DisassemblyLayer");

  ImGui::Text("Count: %d", count);

  if (ImGui::Button("Disassemble"))
  {
    fileToDisassemble = "C:\\dev\\RESweet\\Samples\\test.exe";
    shouldDisassemble = true;
  }

  if (capstoneOutput.IsDisassembled())
  {
    ImGui::Text("Instruction count: %d", capstoneOutput.instructionCount);
    ImGui::Text("Function count: %d", capstoneOutput.functions.size());
  }

  ImGui::End();
}

void DisassemblyLayer::OnEvent(const Event& acEvent)
{

}

void DisassemblyLayer::CapstoneOutput::Destroy()
{
  if (IsDisassembled())
  {
    cs_free(instructions, instructionCount);
    cs_close(&handle);
  }
}

bool DisassemblyLayer::CapstoneOutput::DisassembleLinear(std::shared_ptr<Binary> apBinary)
{
  Section* pText = apBinary->GetTextSection();
  if (!pText)
  {
    spdlog::warn("Could not find text section in binary.");
    return false;
  }

  cs_arch architecture{};
  switch (apBinary->architecture)
  {
  case Binary::Architecture::X86:
    architecture = CS_ARCH_X86;
    break;
  case Binary::Architecture::NONE:
    spdlog::error("No architecture selected");
    return false;
    break;
  default:
    spdlog::error("No matching capstone architecture found");
    return false;
  }

  cs_mode mode{};
  switch (apBinary->mode)
  {
  case Binary::Mode::BITS_32:
    mode = CS_MODE_32;
    break;
  case Binary::Mode::BITS_64:
    mode = CS_MODE_64;
    break;
  case Binary::Mode::NONE:
    spdlog::error("No mode selected");
    return false;
    break;
  default:
    spdlog::error("No matching capstone mode found");
    return false;
  }

  if (cs_open(architecture, mode, &handle) != CS_ERR_OK)
  {
    spdlog::error("Failed to initialize capstone handle");
    return false;
  }

  instructionCount = cs_disasm(handle, pText->pBytes.get(), pText->size, pText->address, 0, &instructions);
  if (instructionCount == 0)
  {
    spdlog::error("Disassembly failed, error: {}", cs_strerror(cs_errno(handle)));
    return false;
  }

  for (size_t i = 0; i < instructionCount; i++)
  {
    cs_insn& instruction = instructions[i];

    static bool hitInt3Last = false;
    if (instruction.id == X86_INS_INT3)
    {
      hitInt3Last = true;
      continue;
    }

    if (hitInt3Last)
    {
      functions[instruction.address] = &instructions[i];
      hitInt3Last = false;
    }

    /*
    printf("0x%016jx: ", instruction.address);
    for (size_t j = 0; j < 16; j++)
    {
      if (j < instruction.size)
        printf("%02x ", instruction.bytes[j]);
      else
        printf("   ");
    }

    printf("%-12s %s\n", instruction.mnemonic, instruction.op_str);
    */
  }

  return true;
}
