#pragma once

#include "BaseParser.h"

#include <string>

class ELFParser : public BaseParser
{
public:

  ELFParser(const std::string& acFile)
    : BaseParser(acFile)
  {}

  Binary Parse() override;

private:

  bool is64Bit = false;
};
