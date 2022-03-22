#pragma once

#include <stdint.h>
#include <string>
#include <vector>

class Binary;
class Section;
class Symbol;

class Symbol {
public:
  enum class Type {
    UKN = 0,
    FUNC = 1,
  };

  Symbol() :
    type(Type::UKN),
    name(),
    addr(0)
  {}

  Type type;
  std::string name;
  uint64_t addr;
};

class Section {
public:
  enum class Type {
    NONE = 0,
    CODE = 1,
    DATA = 2,
  };

  Section() :
    binary(nullptr),
    type(Type::NONE),
    vma(0),
    size(0),
    bytes(nullptr)
  {}

  bool Contains(uint64_t addr) const 
  {
    return (addr >= vma) && (addr - vma < size);
  }

  Binary* binary;
  std::string name;
  Type type;
  uint64_t vma;
  uint64_t size;
  uint8_t* bytes;
};

class Binary {
public:
  enum class Type {
    AUTO = 0,
    ELF = 1,
    PE = 2,
  };

  enum class Arch {
    NONE = 0,
    X86 = 1,
  };

  Binary() :
    type(Type::AUTO),
    arch(Arch::NONE),
    bits(0),
    entry(0)
  {}

  Section* GetTextSection()
  {
    for (Section& section : sections)
    {
      if (section.name == ".text")
        return &section;
    }

    return nullptr;
  }

  std::string filename;
  Type type;
  std::string type_str;
  Arch arch;
  std::string arch_str;
  unsigned bits;
  uint64_t entry;
  std::vector<Section> sections;
  std::vector<Symbol> symbols;
};
