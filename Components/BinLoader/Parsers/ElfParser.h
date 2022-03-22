#pragma once

#include "../BaseParser.h"
#include "../FileFormats.h"

class ElfParser : public BaseParser
{
public:

  ElfParser(Reader&& aReader)
    : BaseParser(std::move(aReader))
  {}

  Binary Parse() override;

private:

  bool is64Bit = false;
};
