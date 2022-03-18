#include "../loader.h"

int main(int argc, char* argv[])
{
  if (argc < 2)
  {
    printf("Usage: %s <binary>\n", argv[0]);
    return 1;
  }

  std::string fname = argv[1];

  Binary bin;
  if (!LoadBinary(fname, &bin, Binary::Type::AUTO))
    return 1;

  printf("loaded binary '%s' %s/%s (%u bits) entry@0x%016jx\n",
         bin.filename.c_str(),
         bin.type_str.c_str(),
         bin.arch_str.c_str(),
         bin.bits, bin.entry);
  
  for (Section& section : bin.sections)
  {
    printf(" 0x%016jx %-8ju %-20s %s\n",
      section.vma, section.size, section.name.c_str(),
      section.type == Section::Type::CODE ? "CODE" : "DATA");
  }

  if (bin.symbols.size() > 0)
  {
    printf("scanned symbol tables\n");
    for (Symbol& symbol : bin.symbols)
    {
      printf(" %-40s 0x%016jx %s\n",
        symbol.name.c_str(), symbol.addr,
        symbol.type == Symbol::Type::FUNC ? "FUNC" : "");
    }
  }

  UnloadBinary(&bin);

  return 0;
}
