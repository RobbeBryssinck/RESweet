#pragma once

#include "../BaseParser.h"
#include "../FileFormats.h"

// TODO: might be cleaner to just split 32 and 64 bit up?
class ElfParser : public BaseParser
{
public:
  ElfParser() = delete;

  ElfParser(Reader&& aReader)
    : BaseParser(std::move(aReader))
  {}

  virtual ~ElfParser() override {}

  std::shared_ptr<Binary> Parse() override;

private:

  void ReadFileClass();
  void ReadElfHeader();
  void ReadSectionHeaders();

  std::string GetSectionName32(ELF::Elf32_Shdr& aSection);
  std::string GetSectionName64(ELF::Elf64_Shdr& aSection);

  bool is64Bit = false;

  // elf header
  union {
    ELF::Elf32_Ehdr elfHeader32;
    ELF::Elf64_Ehdr elfHeader64{};
  };
  // program header
  union {
    ELF::Elf32_Phdr programHeader32;
    ELF::Elf64_Phdr programHeader64{};
  };
  // sections
  union {
    std::vector<ELF::Elf32_Shdr> sections32;
    std::vector<ELF::Elf64_Shdr> sections64{};
  };
};
