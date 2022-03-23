#include "ElfParser.h"

#include <spdlog/spdlog.h>

std::shared_ptr<Binary> ElfParser::Parse()
{
  ReadFileClass();
  ReadElfHeader();
  ReadSectionHeaders();

  std::shared_ptr<Binary> pBinary = std::make_shared<Binary>();

  pBinary->type = Binary::Type::ELF;

  if (is64Bit)
  {
    pBinary->arch = Binary::Arch::X64;
    pBinary->entryPoint = elfHeader64.e_entry;

    pBinary->sections.reserve(sections64.size());
    for (const ELF::Elf64_Shdr& elfSection : sections64)
    {
      std::optional<Section*> section = InitSection(pBinary, elfSection);
      if (section)
        (*section)->name = GetSectionName64(elfSection);
    }
  }
  else
  {
    pBinary->arch = Binary::Arch::X86;
    pBinary->entryPoint = elfHeader32.e_entry;

    pBinary->sections.reserve(sections32.size());
    for (const ELF::Elf32_Shdr& elfSection : sections32)
    {
      std::optional<Section*> section = InitSection(pBinary, elfSection);
      if (section)
        (*section)->name = GetSectionName32(elfSection);
    }
  }

  for (Section& section : pBinary->sections)
  {
    section.pBytes = std::make_unique<uint8_t[]>(section.size);
    reader.position = section.offset;
    reader.ReadImpl(section.pBytes.get(), section.size);

    if (section.name == ".strtab")
    {
      // TODO: some symbols addresses are null?
      if (is64Bit)
      {
        pBinary->symbols.reserve(symbols64.size());
        for (const ELF::Elf64_Sym& elfSymbol : symbols64)
          InitSymbol(pBinary->symbols, elfSymbol, section.offset);
      }
      else
      {
        pBinary->symbols.reserve(symbols32.size());
        for (const ELF::Elf32_Sym& elfSymbol : symbols32)
          InitSymbol(pBinary->symbols, elfSymbol, section.offset);
      }
    }
  }

  return pBinary;
}

void ElfParser::ReadFileClass()
{
  reader.position = 4;
  uint8_t fileClass = 0;
  reader.Read(fileClass);
  reader.Reset();

  is64Bit = fileClass == ELF::ELFCLASS64;
}

void ElfParser::ReadElfHeader()
{
  if (is64Bit)
  {
    reader.Read(elfHeader64);
    // this set position probably shouldn't be necessary,
    // since the program header should come right after the ELF header
    reader.position = elfHeader64.e_phoff;
    reader.Read(programHeader64);
  }
  else
  {
    reader.Read(elfHeader32);
    reader.position = elfHeader32.e_phoff;
    reader.Read(programHeader32);
  }
}

void ElfParser::ReadSectionHeaders()
{
  sections64.clear();
  sections32.clear();

  if (is64Bit)
  {
    reader.position = elfHeader64.e_shoff;

    sections64.reserve(elfHeader64.e_shnum);
    for (size_t i = 0; i < elfHeader64.e_shnum; i++)
    {
      // TODO: advance the reader one section entry? since the first one is null.
      // also, reserve - 1. same for symbols. skip by e_shentsize
      ELF::Elf64_Shdr& section = sections64.emplace_back();
      reader.Read(section);
    }
  }
  else
  {
    reader.position = elfHeader32.e_shoff;

    sections64.reserve(elfHeader32.e_shnum);
    for (size_t i = 0; i < elfHeader32.e_shnum; i++)
    {
      ELF::Elf32_Shdr& section = sections32.emplace_back();
      reader.Read(section);
    }
  }
}

void ElfParser::ReadSymbols(size_t aOffset, size_t aSize)
{
  symbols32.clear();
  symbols64.clear();

  reader.position = aOffset;

  if (is64Bit)
  {
    const size_t count = aSize / sizeof(ELF::Elf64_Sym);
    // TODO: skip first symbol entry, which is null (ala sections)
    symbols64.reserve(count);
    for (size_t i = 0; i < count; i++)
    {
      ELF::Elf64_Sym& symbol = symbols64.emplace_back();
      reader.Read(symbol);
    }
  }
  else
  {
    const size_t count = aSize / sizeof(ELF::Elf32_Sym);
    symbols32.reserve(count);
    for (size_t i = 0; i < count; i++)
    {
      ELF::Elf32_Sym& symbol = symbols32.emplace_back();
      reader.Read(symbol);
    }
  }
}

std::string ElfParser::GetSectionName32(const ELF::Elf32_Shdr& aSection)
{
  if (elfHeader32.e_shstrndx == 0)
    return "";

  const ELF::Elf32_Shdr& section = sections32[elfHeader32.e_shstrndx];
  reader.position = section.sh_offset + aSection.sh_name;
  return reader.ReadString();
}

std::string ElfParser::GetSectionName64(const ELF::Elf64_Shdr& aSection)
{
  if (elfHeader64.e_shstrndx == 0)
    return "";

  const ELF::Elf64_Shdr& section = sections64[elfHeader64.e_shstrndx];
  reader.position = section.sh_offset + aSection.sh_name;
  return reader.ReadString();
}
