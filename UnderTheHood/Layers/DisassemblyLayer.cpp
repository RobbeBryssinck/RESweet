#include "DisassemblyLayer.h"

#include <BinLoader/BaseParser.h>
#include <FileHandling.h>

#include <imgui.h>
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

  ImGui::Begin("Disassembly");

  ImGui::Text("Count: %d", count);

  if (ImGui::Button("Disassemble"))
  {
    fileToDisassemble = OpenFileDialogue();
    shouldDisassemble = true;
  }

  if (capstoneOutput.IsDisassembled())
  {
    ImGui::Text("Instruction count: %d", capstoneOutput.instructionCount);
    ImGui::Text("Function count: %d", capstoneOutput.functions.size());

    static uint64_t address = 0;
    ImGui::InputScalar("Address", ImGuiDataType_U64, &address, 0, 0, "%" PRIx64, ImGuiInputTextFlags_CharsHexadecimal);
    if (ImGui::Button("Get function") && address)
    {
      if (capstoneOutput.functions.contains(address))
      {
        CapstoneOutput::Function& function = capstoneOutput.functions[address];
        spdlog::info("Function address: {:X}, size: {}, instruction count: {}", function.address, function.size, function.instructions.size());

        for (cs_insn& instruction : function.instructions)
        {
          printf("0x%016jx: ", instruction.address);

          for (size_t j = 0; j < 16; j++)
          {
            if (j < instruction.size)
              printf("%02x ", instruction.bytes[j]);
            else
              printf("   ");
          }

          printf("%-12s %s\n", instruction.mnemonic, instruction.op_str);
        }
      }
      else
        spdlog::error("Function with address {:X} not found.", address);
    }
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

  instructionCount = cs_disasm(handle, pText->pBytes.get(), pText->size, pText->offset, 0, &instructions);
  if (instructionCount == 0)
  {
    spdlog::error("Disassembly failed, error: {}", cs_strerror(cs_errno(handle)));
    return false;
  }

  for (size_t i = 0; i < instructionCount; i++)
  {
    cs_insn& instruction = instructions[i];

    if (instruction.id == X86_INS_INT3)
      continue;

    Function& function = functions[instruction.address];
    function.address = instruction.address;

    do
    {
      function.instructions.push_back(instruction);

      i++;
      if (i >= instructionCount)
        break;

      instruction = instructions[i];
    } while (instruction.id != X86_INS_INT3);

    // TODO: is this right if i >= instructionCount?
    function.size = instruction.address - function.address;

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
