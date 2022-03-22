#include "PEParser.h"

Binary PEParser::Parse()
{
  ReadDOSHeader();
  ReadPEHeader();
  ReadOptionalHeader();

  return Binary{};
}

void PEParser::ReadDOSHeader()
{
  Read(&dosHeader);
}

void PEParser::ReadPEHeader()
{
  position = dosHeader.e_lfanew;
  Read(&signature);
  Read(&peHeader);
}

void PEParser::ReadOptionalHeader()
{
  WORD magic = 0;
  Read(&magic, true);

  is64Bit = magic == OptionalMagic::PE32PLUS;

  if (is64Bit)
    Read(&optionalHeader64);
  else
    Read(&optionalHeader);
}
