#include "PeParser.h"

Binary PeParser::Parse()
{
  ReadDOSHeader();
  ReadPEHeader();
  ReadOptionalHeader();
  ReadSectionHeaders();

  return Binary{};
}

void PeParser::ReadDOSHeader()
{
  reader.Read(dosHeader);
}

void PeParser::ReadPEHeader()
{
  reader.position = dosHeader.AddressOfNewExeHeader;
  reader.Read(signature);
  reader.Read(peHeader);
}

void PeParser::ReadOptionalHeader()
{
  uint16_t magic = 0;
  reader.Read(magic, true);

  is64Bit = magic == OptionalMagic::PE32PLUS;

  if (is64Bit)
    reader.Read(optionalHeader64);
  else
    reader.Read(optionalHeader32);
}

void PeParser::ReadSectionHeaders()
{
  sections.clear();
  sections.reserve(peHeader.NumberOfSections);

  for (uint32_t i = 0; i < peHeader.NumberOfSections; i++)
  {
    PE::coff_section& section = sections.emplace_back();
    reader.Read(section);
  }
}
