#include "DisassemblyLayer.h"

#include <BinLoader/BaseParser.h>
#include <FileHandling.h>

#include <imgui.h>
#include <spdlog/spdlog.h>

#include <queue>
#include <set>

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
    //capstoneOutput.DisassembleLinear(pBinary);
    capstoneOutput.DisassembleRecursive(pBinary);

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
          DisassemblyLayer::CapstoneOutput::PrintInstruction(&instruction);
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

void DisassemblyLayer::CapstoneOutput::PrintInstruction(cs_insn* apInstruction)
{
  printf("0x%016jx: ", apInstruction->address);

  for (size_t j = 0; j < 16; j++)
  {
    if (j < apInstruction->size)
      printf("%02x ", apInstruction->bytes[j]);
    else
      printf("   ");
  }

  printf("%-12s %s\n", apInstruction->mnemonic, apInstruction->op_str);
}

void DisassemblyLayer::CapstoneOutput::Destroy()
{
  if (IsDisassembled())
  {
    cs_free(instructions, instructionCount);
    cs_close(&handle);
  }
}

bool DisassemblyLayer::CapstoneOutput::SetupDisassembly(std::shared_ptr<Binary> apBinary)
{
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

  return true;
}

bool DisassemblyLayer::CapstoneOutput::DisassembleLinear(std::shared_ptr<Binary> apBinary)
{
  if (!SetupDisassembly(apBinary))
    return false;

  Section* pText = apBinary->GetTextSection();
  if (!pText)
  {
    spdlog::warn("Could not find text section in binary.");
    return false;
  }

  instructionCount = cs_disasm(handle, pText->pBytes.get(), pText->size, pText->virtualAddress + apBinary->imageBase, 0, &instructions);
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
  }

  return true;
}

bool DisassemblyLayer::CapstoneOutput::DisassembleRecursive(std::shared_ptr<Binary> apBinary)
{
  if (!SetupDisassembly(apBinary))
    return false;

  Section* pText = apBinary->GetTextSection();
  if (!pText)
  {
    spdlog::warn("Could not find text section in binary.");
    return false;
  }

  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

  cs_insn* instruction = cs_malloc(handle);
  if (!instruction)
  {
    spdlog::error("Disassembly failed: out of memory");
    cs_close(&handle);
    return false;
  }

  std::queue<uint64_t> addressQueue{};

  if (pText->Contains(apBinary->entryPoint))
    addressQueue.push(apBinary->entryPoint);

  for (Symbol& symbol : apBinary->symbols)
  {
    if (symbol.type == Symbol::Type::FUNC && pText->Contains(symbol.address))
      addressQueue.push(symbol.address);
  }

  std::set<uint64_t> processedAddresses{};
  while (!addressQueue.empty())
  {
    uint64_t address = addressQueue.front();
    addressQueue.pop();

    if (processedAddresses.contains(address))
      continue;

    uint64_t offset = address - pText->virtualAddress;
    const uint8_t* pInstructions = pText->pBytes.get() + offset;
    size_t size = pText->size - offset;

    printf("# Disassembling new target: 0x%016jx\n", offset);

    uint64_t loadedAddress = address + apBinary->imageBase;

    Function& function = functions[loadedAddress];
    function.address = loadedAddress;

    while (cs_disasm_iter(handle, &pInstructions, &size, &address, instruction))
    {
      if (instruction->id == X86_INS_INVALID || instruction->size == 0)
        break;

      processedAddresses.insert(instruction->address);

      DisassemblyLayer::CapstoneOutput::PrintInstruction(instruction);
      function.instructions.push_back(*instruction);

      bool isControlInstruction = false;
      for (size_t i = 0; i < instruction->detail->groups_count; i++)
      {
        isControlInstruction = IsControlInstruction(instruction->detail->groups[i]);

        if (isControlInstruction)
          break;
      }

      if (!isControlInstruction)
      {
        if (instruction->id == X86_INS_HLT)
          break;

        continue;
      }

      int64_t target = 0;
      cs_x86_op* operand;
      for (size_t i = 0; i < instruction->detail->groups_count; i++)
      {
        if (IsControlInstruction(instruction->detail->groups[i]))
        {
          for (size_t j = 0; j < instruction->detail->x86.op_count; j++)
          {
            operand = &instruction->detail->x86.operands[j];
            if (operand->type == X86_OP_IMM)
              target = operand->imm;
          }
        }
      }

      if (target && !processedAddresses.contains(target) && pText->Contains(target))
      {
        addressQueue.push(target);
        printf(" -> New target found: 0x%016jx\n", target);
      }

      bool stop = false;
      switch (instruction->id)
      {
      case X86_INS_JMP:
      case X86_INS_LJMP:
      case X86_INS_RET:
      case X86_INS_RETF:
      case X86_INS_RETFQ:
        stop = true;
        break;
      default:
        stop = false;
      }

      if (stop)
        break;
    }

    printf("----------\n");

    //function.size = ?
    //function.instructions = ?
  }

  instructionCount = 1;
  instructions = instruction;

  /*
  cs_free(instruction, 1);
  cs_close(&handle);
  */

  return true;
}

bool DisassemblyLayer::CapstoneOutput::IsControlInstruction(uint8_t aInstruction) const
{
  switch (aInstruction)
  {
  case CS_GRP_JUMP:
  case CS_GRP_CALL:
  case CS_GRP_RET:
  case CS_GRP_IRET:
    return true;
  default:
    return false;
  }
}