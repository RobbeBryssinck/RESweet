#include "Disassembly.h"

#include <spdlog/spdlog.h>

#include <memory>
#include <unordered_map>
#include <queue>
#include <set>

namespace Disassembly
{

// TODO: std optional?
csh SetupDisassembly(std::shared_ptr<Binary> apBinary)
{
  csh handle = 0;

  cs_arch architecture{};
  switch (apBinary->architecture)
  {
  case Binary::Architecture::X86:
    architecture = CS_ARCH_X86;
    break;
  case Binary::Architecture::NONE:
    spdlog::error("No architecture selected");
    return handle;
    break;
  default:
    spdlog::error("No matching capstone architecture found");
    return handle;
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
    return handle;
    break;
  default:
    spdlog::error("No matching capstone mode found");
    return handle;
  }

  if (cs_open(architecture, mode, &handle) != CS_ERR_OK)
  {
    spdlog::error("Failed to initialize capstone handle");
    return handle;
  }

  return handle;
}

bool IsControlInstruction(uint8_t aInstruction)
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

bool IsEndOfFunction(csh aHandle, cs_insn* apInstruction, size_t aSize, uint64_t aAddress, const uint8_t* apData)
{
  cs_insn* pInstruction = apInstruction;
  size_t size = aSize;
  uint64_t address = aAddress;
  const uint8_t* pData = apData;

  if (!cs_disasm_iter(aHandle, &pData, &size, &address, pInstruction))
    return true;

  // TODO: this is flawed, not all functions have INT3 padding
  if (pInstruction->id == X86_INS_INVALID
      || pInstruction->id == X86_INS_INT3
      || pInstruction->size == 0)
    return true;

  return false;
}

bool DisassembleLinear(std::shared_ptr<Binary> apBinary, Functions& aFunctions)
{
  csh handle = SetupDisassembly(apBinary);
  if (handle == 0)
    return false;

  Section* pText = apBinary->GetTextSection();
  if (!pText)
  {
    spdlog::warn("Could not find text section in binary.");
    return false;
  }

  cs_insn* instructions;
  size_t instructionCount = cs_disasm(handle, pText->pBytes.get(), pText->size, pText->virtualAddress + apBinary->imageBase, 0, &instructions);
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

    Function& function = aFunctions[instruction.address];
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

  cs_free(instructions, instructionCount);
  cs_close(&handle);

  return true;
}

bool DisassembleRecursive(std::shared_ptr<Binary> apBinary, Functions& aFunctions)
{
  csh handle = SetupDisassembly(apBinary);
  if (handle == 0)
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
    addressQueue.push(apBinary->entryPoint + apBinary->imageBase);

  for (Symbol& symbol : apBinary->symbols)
  {
    if (symbol.type == Symbol::Type::FUNC && pText->Contains(symbol.address))
      addressQueue.push(symbol.address + apBinary->imageBase);
  }

  std::set<uint64_t> processedAddresses{};
  while (!addressQueue.empty())
  {
    uint64_t address = addressQueue.front();
    addressQueue.pop();

    if (processedAddresses.contains(address))
      continue;

    uint64_t offset = address - pText->virtualAddress - apBinary->imageBase;
    const uint8_t* pData = pText->pBytes.get() + offset;
    size_t size = pText->size - offset;

    spdlog::debug("Disassembling new target: 0x%016jx\n", address);

    Function& function = aFunctions[address];
    function.address = address;
    function.name = fmt::format("sub_{:X}", address);

    while (cs_disasm_iter(handle, &pData, &size, &address, instruction))
    {
      if (instruction->id == X86_INS_INVALID || instruction->size == 0)
        break;

      processedAddresses.insert(instruction->address);

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

      if (target && !processedAddresses.contains(target) && pText->Contains(target - apBinary->imageBase))
        addressQueue.push(target);

      if (IsEndOfFunction(handle, instruction, size, address, pData))
        break;

      // if function only contains 1 jump instruction, assume it's its own thing
      if (instruction->id == X86_INS_JMP && function.instructions.size() == 1)
        break;
    }

    // TODO:
    //function.size = ?
    //function.instructions = ?
  }

  cs_free(instruction, 1);
  cs_close(&handle);

  return true;
}

Functions Disassemble(std::shared_ptr<Binary> apBinary, const bool aRecursive)
{
  Functions functions{};

  if (aRecursive)
    DisassembleRecursive(apBinary, functions);
  else
    DisassembleLinear(apBinary, functions);

  return functions;
}

} // namespace Disassembly