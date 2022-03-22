/*
#include <stdio.h>
#include <queue>
#include <map>
#include <string>
#include <capstone/capstone.h>
#include <loader.h>

bool Disassemble(Binary* bin);
void PrintInstruction(cs_insn* ins);
bool IsCsCflowGroup(uint8_t g);
bool IsCsCflowInstruction(cs_insn* ins);
bool IsCsUnconditionalCflowInstruction(cs_insn* ins);
uint64_t GetCsInstructionImmediateTarget(cs_insn* ins);

int main2(int argc, char *argv[])
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

  // Detailed disassembly for control flow
  cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);

  cs_insn* cs_ins = cs_malloc(dis);
  if (!cs_ins)
  {
    fprintf(stderr, "Out of memory\n");
    cs_close(&dis);
    return false;
  }

  std::queue<uint64_t> Q;
  uint64_t entryAddr = bin->entry;
  if (text->Contains(entryAddr))
    Q.push(entryAddr);

  printf("Entry point: 0x%016jx\n", entryAddr);

  for (Symbol& symbol : bin->symbols)
  {
    if (symbol.type == Symbol::Type::FUNC && text->Contains(symbol.addr))
    {
      Q.push(symbol.addr);
      printf("function symbol: 0x%016jx\n", symbol.addr);
    }
  }

  // TODO: unordered_map?
  std::map<uint64_t, bool> seen;
  while (!Q.empty())
  {
    uint64_t addr = Q.front();
    Q.pop();

    if (seen[addr])
      continue;

    uint64_t offset = addr - text->vma;
    const uint8_t* pc = text->bytes + offset;
    size_t n = text->size - offset;
    while (cs_disasm_iter(dis, &pc, &n, &addr, cs_ins))
    {
      if (cs_ins->id == X86_INS_INVALID || cs_ins->size == 0)
        break;
      
      seen[cs_ins->address] = true;
      PrintInstruction(cs_ins);

      if (IsCsCflowInstruction(cs_ins))
      {
        uint64_t target = GetCsInstructionImmediateTarget(cs_ins);
        if (target && !seen[target] && text->Contains(target))
        {
          Q.push(target);
          printf(" -> new target: 0x%016jx\n", target);
        }

        if (IsCsUnconditionalCflowInstruction(cs_ins))
          break;
      }
      else if (cs_ins->id == X86_INS_HLT)
        break;
    }
    printf("---------------\n");
  }

  cs_free(cs_ins, 1);
  cs_close(&dis);
  
  return true;
}

void PrintInstruction(cs_insn* ins)
{
  printf("0x%017jx: ", ins->address);

  for (size_t i = 0; i < 17; i++)
  {
    if (i < ins->size)
      printf("%02x ", ins->bytes[i]);
    else
      printf("   ");
  }

  printf("%-12s %s \n", ins->mnemonic, ins->op_str);
}

bool IsCsCflowGroup(uint8_t g)
{
  switch (g)
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

bool IsCsCflowInstruction(cs_insn* ins)
{
  for (size_t i = 0; i < ins->detail->groups_count; i++)
  {
    if (IsCsCflowGroup(ins->detail->groups[i]))
      return true;
  }

  return false;
}

bool IsCsUnconditionalCflowInstruction(cs_insn* ins)
{
  switch (ins->id)
  {
  case X86_INS_JMP:
  case X86_INS_LJMP:
  case X86_INS_RET:
  case X86_INS_RETF:
  case X86_INS_RETFQ:
    return true;
  default:
    return false;
  }
}

uint64_t GetCsInstructionImmediateTarget(cs_insn* ins)
{
  cs_x86_op* cs_op;

  for (size_t i = 0; i < ins->detail->groups_count; i++)
  {
    if (IsCsCflowGroup(ins->detail->groups[i]))
    {
      for (size_t j = 0; j < ins->detail->x86.op_count; j++)
      {
        cs_op = &ins->detail->x86.operands[j];
        if (cs_op->type == X86_OP_IMM)
          return cs_op->imm;
      }
    }
  }

  return 0;
}
*/
