#pragma once

#include <stdint.h>
#include <string>
#include <vector>
#include <memory>
#include <optional>

class Binary;
class Section;
class Symbol;

class Symbol {
public:
  enum class Type {
    NONE = 0,
    FUNC = 1,
  };

  Type type = Type::NONE;
  std::string name = "";
  uint64_t address = 0;
};

class Section {
public:
  enum class Type {
    NONE = 0,
    CODE = 1,
    DATA = 2,
  };

  constexpr bool Contains(uint64_t aAddress) const
  {
    return (aAddress >= virtualAddress) && (aAddress - virtualAddress < size);
  }

  // TODO: binary.cpp
  /*
  bool ContainsImageBase(uint64_t aAddress) const 
  {
    return (aAddress >= (virtualAddress + pBinary->imageBase)) && (aAddress - (virtualAddress + pBinary->imageBase) < size);
  }
  */

  std::shared_ptr<Binary> pBinary{};
  std::string name = "";
  Type type = Type::NONE;
  uint64_t address = 0;
  uint64_t virtualAddress = 0;
  uint64_t size = 0;
  std::unique_ptr<uint8_t[]> pBytes{};
};

class Binary {
public:
  enum class Type {
    NONE = 0,
    ELF = 1,
    PE = 2,
  };

  enum class Architecture {
    NONE = 0,
    X86 = 1,
  };

  enum class Mode {
    NONE = 0,
    BITS_32 = 1,
    BITS_64 = 2,
  };

  const Section* GetTextSection() const
  {
    for (const Section& section : sections)
    {
      if (section.name == ".text")
        return &section;
    }

    return nullptr;
  }

  std::string filename = "";
  Type type = Type::NONE;
  Architecture architecture = Architecture::NONE;
  Mode mode = Mode::NONE;
  uint64_t entryPoint = 0;
  uint64_t imageBase = 0;
  std::vector<Section> sections{};
  std::vector<Symbol> symbols{};
};
