/*
#include <stdio.h>
#include <string>
#include <capstone/capstone.h>
#include <loader.h>
#include <memory>
#include <spdlog/spdlog.h>
#include <spdlog/spdlog-inl.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

bool Disassemble(Binary* bin);

void InitializeLogger()
{
  auto console = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  console->set_pattern("%^[%H:%M:%S] [%l]%$ %v");
  auto logger = std::make_shared<spdlog::logger>("", spdlog::sinks_init_list{ console });
  set_default_logger(logger);
}

int main(int argc, char* argv[])
{
  if (argc < 2)
  {
    spdlog::error("Usage: {} <binary>\n", argv[0]);
    return 1;
  }

  std::string fname = argv[1];

  Binary bin;
  if (!LoadBinary(fname, &bin, Binary::Type::AUTO))
    return 1;

  if (Disassemble(&bin) < 0)
  {
    return 1;
  }

  UnloadBinary(&bin);

  return 0;
}

bool Disassemble(Binary* bin)
{
  Section* text = bin->GetTextSection();
  if (!text)
  {
    fprintf(stderr, "Nothing to disassemble\n");
    return false;
  }

  csh dis;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &dis) != CS_ERR_OK)
  {
    fprintf(stderr, "Failed to open Capstone\n");
    return false;
  }

  cs_insn* insns;
  size_t n = cs_disasm(dis, text->bytes, text->size, text->vma, 0, &insns);
  if (n <= 0)
  {
    fprintf(stderr, "Disassembly error: %s\n",
            cs_strerror(cs_errno(dis)));
    return false;
  }

  for (size_t i = 0; i < n; i++)
  {
    static bool wasLastINT3 = false;
    if (insns[i].id == X86_INS_INT3)
    {
      if (!wasLastINT3)
        printf("\n");
      wasLastINT3 = true;
      continue;
    }

    if (wasLastINT3)
      printf("sub_%jx():\n", insns[i].address);

    wasLastINT3 = false;

    printf("0x%016jx: ", insns[i].address);
    for(size_t j = 0; j < 16; j++) {
      if(j < insns[i].size)
        printf("%02x ", insns[i].bytes[j]);
      else
        printf("   ");
    }

    printf("%-12s %s\n", insns[i].mnemonic, insns[i].op_str);
  }

  cs_free(insns, n);
  cs_close(&dis);

  return true;
}
*/
