#include <stdio.h>
#include <queue>
#include <map>
#include <string>
#include <capstone/capstone.h>
#include "../binloader/loader.h"

int Disassemble(Binary* bin);
void PrintInstruction(cs_insn* ins);
bool IsCsCflowGroup(uint8_t g);
bool IsCsCflowInstruction(cs_insn* ins);
bool IsCsUnconditionCflowInstruction(cs_insn* ins);
uint64_t GetCsInstructionImmediateTarget(cs_insn* ins);

int main(int argc, char *argv[])
{
  if(argc < 2) {
    printf("Usage: %s <binary>\n", argv[0]);
    return 1;
  }

  std::string fname = argv[1];
  Binary bin;
  if(LoadBinary(fname, &bin, Binary::Type::AUTO) < 0) {
    return 1;
  }

  if(Disassemble(&bin) < 0) {
    return 1;
  }

  UnloadBinary(&bin);
  return 0;
}
