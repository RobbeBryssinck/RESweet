#pragma once

#include "../BaseParser.h"
#include "../FileFormats.h"

class ElfParser : public BaseParser
{
public:

  ElfParser(Reader&& aReader)
    : BaseParser(std::move(aReader))
  {}

  std::shared_ptr<Binary> Parse() override;

private:

  bool is64Bit = false;
};
