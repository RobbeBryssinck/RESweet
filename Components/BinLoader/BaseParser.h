#pragma once

#include "Binary.h"
#include "Reader.h"

namespace Parsing
{

enum class Format
{
  UNSUPPORTED,
  PE,
  ELF
};

Format GetFormat(Reader& aReader);
Binary ParseFile(const std::string& acFile);

} // namespace Parsing

class BaseParser
{
public:
  BaseParser() = delete;

  BaseParser(Reader&& aReader)
    : reader(std::move(aReader))
  {}

  virtual Binary Parse() = 0;

protected:
  Reader reader;
};
