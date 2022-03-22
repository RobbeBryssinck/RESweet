#include "ELFParser.h"

std::shared_ptr<Binary> ElfParser::Parse()
{
  ReadFileClass();
  ReadElfHeader();
  ReadSectionHeaders();
  // TODO: ReadSymbols();

  std::shared_ptr<Binary> pBinary = std::make_shared<Binary>();

  pBinary->type = Binary::Type::ELF;

  if (is64Bit)
  {
    pBinary->arch = Binary::Arch::X64;
    pBinary->entryPoint = elfHeader64.e_entry;

    pBinary->sections.reserve(sections64.size());
    for (ELF::Elf64_Shdr& elfSection : sections64)
    {
      if (elfSection.sh_size == 0)
        continue;

      Section& section = pBinary->sections.emplace_back();
      section.pBinary = pBinary;
      section.name = GetSectionName64(elfSection.sh_name);
      // TODO: improve this
      section.type = (elfSection.sh_flags & 0x4) ? Section::Type::CODE : Section::Type::DATA;
      section.address = elfSection.sh_addr;
      section.size = elfSection.sh_size;
      section.offset = elfSection.sh_offset;
    }
  }
  else
  {
    pBinary->arch = Binary::Arch::X86;
    pBinary->entryPoint = elfHeader32.e_entry;

    pBinary->sections.reserve(sections32.size());
    for (ELF::Elf32_Shdr& elfSection : sections32)
    {
      if (elfSection.sh_size == 0)
        continue;

      Section& section = pBinary->sections.emplace_back();
      section.pBinary = pBinary;
      section.name = GetSectionName32(elfSection.sh_name);
      section.type = (elfSection.sh_flags & 0x4) ? Section::Type::CODE : Section::Type::DATA;
      section.address = elfSection.sh_addr;
      section.size = elfSection.sh_size;
      section.offset = elfSection.sh_offset;
    }
  }

  for (Section& section : pBinary->sections)
  {
    section.pBytes = std::make_unique<uint8_t[]>(section.size);
    reader.position = section.offset;
    reader.ReadImpl(section.pBytes.get(), section.size);
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
    // TODO: this set position probably shouldn't be necessary,
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

std::string ElfParser::GetSectionName32(uint32_t aOffset)
{
  ELF::Elf32_Shdr& section = sections32[elfHeader32.e_shstrndx];
  reader.position = section.sh_offset;
  reader.position += aOffset;
  return reader.ReadString();
}

std::string ElfParser::GetSectionName64(uint64_t aOffset)
{
  ELF::Elf64_Shdr& section = sections64[elfHeader64.e_shstrndx];
  reader.position = section.sh_offset;
  reader.position += aOffset;
  return reader.ReadString();
}
