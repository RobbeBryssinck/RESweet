#include "BaseParser.h"

#include "Parsers/PeParser.h"
#include "Parsers/ElfParser.h"

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
  case 0x464C457F:
    return Format::ELF;
  case 0x00905A4D:
    return Format::PE;
  default:
    return Format::UNSUPPORTED;
  }
}

std::shared_ptr<Binary> ParseFile(Reader& aReader)
{
  std::unique_ptr<BaseParser> pParser{};

  // TODO: confirm std::move() stuff for Reader
  switch (GetFormat(aReader))
  {
  case Format::PE:
    pParser = std::make_unique<PeParser>(std::move(aReader));
    break;
  case Format::ELF:
    pParser = std::make_unique<ElfParser>(std::move(aReader));
    break;
  case Format::UNSUPPORTED:
  default:
    spdlog::error("Format not supported!");
    return std::make_shared<Binary>();
  }

  std::shared_ptr<Binary> pBinary = pParser->Parse();

  return pBinary;
}

std::shared_ptr<Binary> ParseFile(const std::string& acFile)
{
  Reader reader{};
  if (!reader.LoadFromFile(acFile))
  {
    spdlog::error("Failed to load to-parse file");
    return nullptr;
  }

  std::shared_ptr<Binary> pBinary = ParseFile(reader);

  // TODO: if ParseFile(reader) is directly called, no filename is set
  // this prolly doesnt matter, we dont use it rn anyway
  pBinary->filename = acFile;

  return pBinary;
}

} // namespace Parsing
