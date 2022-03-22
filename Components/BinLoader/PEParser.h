#pragma once

#include "BaseParser.h"

#include <string>

// TODO: this is gonna crap on linux obviously, just copy the structs from winnt.h
#include <Windows.h>

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

  bool is64Bit = false;

  _IMAGE_DOS_HEADER dosHeader{};

  uint32_t signature{};
  _IMAGE_FILE_HEADER peHeader{};

  _IMAGE_OPTIONAL_HEADER optionalHeader{};
  _IMAGE_OPTIONAL_HEADER64 optionalHeader64{};
};
