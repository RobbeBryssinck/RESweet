#pragma once

#include "BaseParser.h"

#include <string>
#include <Windows.h>

class PEParser : public BaseParser
{
public:

  PEParser(const std::string& acFile)
    : BaseParser(acFile)
  {}

  Binary Parse() override;

private:

  _IMAGE_DOS_HEADER dosHeader{};
};
