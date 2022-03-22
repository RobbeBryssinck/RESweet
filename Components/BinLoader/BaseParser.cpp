#include "BaseParser.h"

#include "Parsers/PEParser.h"
#include "Parsers/ELFParser.h"

#include <filesystem>
#include <fstream>
#include <spdlog/spdlog.h>

namespace Parsing
{

Format GetFormat(Reader& aReader)
{
  uint32_t magic = 0;
  aReader.Read(magic);
  aReader.Reset();

  switch (magic)
  {
  // TODO: delve further to check for 32/64 bit?
  case 0x464C457F:
    return Format::ELF;
  case 0x00905A4D:
    return Format::PE;
  default:
    return Format::UNSUPPORTED;
  }
}

std::shared_ptr<Binary> ParseFile(const std::string& acFile)
{
  // TODO: either do bool Setup() or check for failure
  Reader reader(acFile);

  std::unique_ptr<BaseParser> pParser{};

  switch (GetFormat(reader))
  {
  case Format::PE:
    pParser = std::make_unique<PeParser>(std::move(reader));
    break;
  case Format::ELF:
    pParser = std::make_unique<ElfParser>(std::move(reader));
    break;
  case Format::UNSUPPORTED:
  default:
    spdlog::error("Format not supported!");
    return std::make_shared<Binary>();
  }

  std::shared_ptr<Binary> pBinary = pParser->Parse();

  pBinary->filename = acFile;

  return pBinary;
}

} // namespace Parsing