#include "PEParser.h"

Binary PEParser::Parse()
{
  Read(&dosHeader);

  return Binary{};
}
