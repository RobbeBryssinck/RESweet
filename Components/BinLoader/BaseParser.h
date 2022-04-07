#pragma once

#include "Binary.h"
#include <Reader.h>

namespace Parsing
{

enum class Format
{
  UNSUPPORTED,
  PE,
  ELF
};

Format GetFormat(Reader& aReader);
std::shared_ptr<Binary> ParseFile(const std::string& acFile);

} // namespace Parsing

class BaseParser
{
public:
  BaseParser() = delete;

  BaseParser(Reader&& aReader)
    : reader(std::move(aReader))
  {}

  BaseParser(const BaseParser&) = default;
  BaseParser& operator=(const BaseParser&) = default;

  virtual ~BaseParser() {};
  virtual std::shared_ptr<Binary> Parse() = 0;

protected:
  Reader reader;
};
