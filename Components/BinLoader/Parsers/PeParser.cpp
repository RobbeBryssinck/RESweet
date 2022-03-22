#include "PeParser.h"

std::shared_ptr<Binary> PeParser::Parse()
{
  ReadDOSHeader();
  ReadPEHeader();
  ReadOptionalHeader();
  ReadSectionHeaders();

  std::shared_ptr<Binary> pBinary = std::make_shared<Binary>();

  pBinary->type = Binary::Type::PE;

  if (is64Bit)
  {
    pBinary->arch = Binary::Arch::X64;
    pBinary->entryPoint = optionalHeader64.AddressOfEntryPoint;
  }
  else
  {
    pBinary->arch = Binary::Arch::X86;
    pBinary->entryPoint = optionalHeader32.AddressOfEntryPoint;
  }

  pBinary->sections.reserve(peHeader.NumberOfSections);

  for (PE::coff_section& peSection : sections)
  {
    Section& section = pBinary->sections.emplace_back();
    section.pBinary = pBinary;
    section.name = peSection.Name;
    // TODO: revisit this, this might have to be more comprehensive to catch everything
    section.type = peSection.IsCode() ? Section::Type::CODE : Section::Type::DATA;
    section.address = peSection.PointerToRawData;
    section.size = peSection.SizeOfRawData;

    if (section.size == 0)
      continue;

    section.pBytes = std::make_unique<uint8_t[]>(section.size);
    reader.position = section.address;
    reader.ReadImpl(section.pBytes.get(), section.size);
  }

  // TODO: symbols

  return pBinary;
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
