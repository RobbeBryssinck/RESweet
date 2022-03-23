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
  void ReadSymbols(size_t aPosition, size_t aSize);

  template <class T>
  std::optional<Section*> InitSection(std::shared_ptr<Binary> apBinary, const T& aElfSection)
  {
    // TODO: reconsider this check
    if (aElfSection.sh_size == 0)
      return std::nullopt;

    Section& section = apBinary->sections.emplace_back();
    section.pBinary = apBinary;
    // TODO: improve this
    section.type = (aElfSection.sh_flags & 0x4) ? Section::Type::CODE : Section::Type::DATA;
    section.address = aElfSection.sh_addr;
    section.size = aElfSection.sh_size;
    section.offset = aElfSection.sh_offset;

    if (section.name == ".symtab")
      ReadSymbols(section.offset, section.size);

    return { &section };
  }

  template <class T>
  void InitSymbol(std::vector<Symbol>& aSymbols, const T& aElfSymbol, const size_t aStringTableOffset)
  {
    // TODO: improve this
    Symbol& symbol = aSymbols.emplace_back();
    symbol.type = aElfSymbol.getType() == ELF::STT_FUNC ? Symbol::Type::FUNC : Symbol::Type::NONE;
    symbol.address = aElfSymbol.st_value;

    if (aElfSymbol.st_name)
    {
      reader.position = aStringTableOffset + aElfSymbol.st_name;
      symbol.name = reader.ReadString();
    }
  }

  std::string GetSectionName32(const ELF::Elf32_Shdr& aSection);
  std::string GetSectionName64(const ELF::Elf64_Shdr& aSection);

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
  // symbols
  union {
    std::vector<ELF::Elf32_Sym> symbols32;
    std::vector<ELF::Elf64_Sym> symbols64{};
  };
};
