#include "PEParser.h"

Binary PEParser::Parse()
{
  ReadDOSHeader();
  ReadPEHeader();
  ReadOptionalHeader();
  ReadSectionHeaders();

  return Binary{};
}

void PEParser::ReadDOSHeader()
{
  Read(dosHeader);
}

void PEParser::ReadPEHeader()
{
  position = dosHeader.AddressOfNewExeHeader;
  Read(signature);
  Read(peHeader);
}

void PEParser::ReadOptionalHeader()
{
  uint16_t magic = 0;
  Read(magic, true);

  is64Bit = magic == OptionalMagic::PE32PLUS;

  if (is64Bit)
    Read(optionalHeader64);
  else
    Read(optionalHeader32);
}

void PEParser::ReadSectionHeaders()
{
  sections.clear();
  sections.reserve(peHeader.NumberOfSections);

  for (uint32_t i = 0; i < peHeader.NumberOfSections; i++)
  {
    PE::coff_section& section = sections.emplace_back();
    Read(section);
  }
}
