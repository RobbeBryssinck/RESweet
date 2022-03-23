#include "Disassembly.h"

#include <capstone/capstone.h>
#include <spdlog/spdlog.h>

#include <BaseParser.h>

namespace Disassembly
{

struct CapstoneData
{
  static std::optional<CapstoneData> BinaryToCapstone(std::shared_ptr<Binary> apBinary)
  {
    std::optional<CapstoneData> result = CapstoneData();

    switch (apBinary->architecture)
    {
    case Binary::Architecture::X86:
      result->architecture = CS_ARCH_X86;
      break;
    case Binary::Architecture::NONE:
      spdlog::error("No architecture selected");
      return std::nullopt;
      break;
    default:
      spdlog::error("No matching capstone architecture found");
      return std::nullopt;
    }

    switch (apBinary->mode)
    {
    case Binary::Mode::BITS_32:
      result->mode = CS_MODE_32;
      break;
    case Binary::Mode::BITS_64:
      result->mode = CS_MODE_64;
      break;
    case Binary::Mode::NONE:
      spdlog::error("No mode selected");
      return std::nullopt;
      break;
    default:
      spdlog::error("No matching capstone mode found");
      return std::nullopt;
    }

    return result;
  }

  cs_arch architecture;
  cs_mode mode;
};

bool DisassembleLinear(std::shared_ptr<Binary> apBinary)
{
  Section* pText = apBinary->GetTextSection();
  if (!pText)
  {
    spdlog::warn("Could not find text section in binary.");
    return false;
  }

  std::optional<CapstoneData> capstoneData = CapstoneData::BinaryToCapstone(apBinary);
  if (!capstoneData)
  {
    spdlog::error("Failed to convert binary data to capstone data");
    return false;
  }

  csh csHandle;
  if (cs_open(capstoneData->architecture, capstoneData->mode, &csHandle) != CS_ERR_OK)
  {
    spdlog::error("Failed to initialize capstone handle");
    return false;
  }

  cs_insn* instructions;
  size_t instructionCount = cs_disasm(csHandle, pText->pBytes.get(), pText->size, pText->address, 0, &instructions);
  if (instructionCount == 0)
  {
    spdlog::error("Disassembly failed, error: {}", cs_strerror(cs_errno(csHandle)));
    return false;
  }

  for (size_t i = 0; i < instructionCount; i++)
  {
    cs_insn& instruction = instructions[i];
    if (instruction.id == X86_INS_INT3)
      continue;

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

  cs_free(instructions, instructionCount);
  cs_close(&csHandle);

  return false;
}

} // namespace Disassembly
