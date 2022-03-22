#pragma once

#include "BaseParser.h"
#include "FileFormats.h"

#include <string>

class PEParser : public BaseParser
{
public:

  PEParser(const std::string& acFile)
    : BaseParser(acFile)
  {}

  Binary Parse() override;

private:

  enum OptionalMagic
  {
    PE32 = 0x10B,
    PE32PLUS = 0x20b,
  };

  void ReadDOSHeader();
  void ReadPEHeader();
  void ReadOptionalHeader();
  void ReadSectionHeaders();

  bool is64Bit = false;

  PE::dos_header dosHeader{};
  uint32_t signature{};
  PE::coff_file_header peHeader{};
  union {
    PE::pe32_header optionalHeader32;
    PE::pe32plus_header optionalHeader64{};
  };
  std::vector<PE::coff_section> sections{};
};
