#pragma once

#include <Reader.h>

#include <spdlog/spdlog.h>

#include <string>
#include <vector>
#include <ctype.h>

namespace Strings
{

// TODO: ehh?
bool IsEndOfStringChar(char aChar)
{
  return aChar == '\00' || aChar == '\n';
}

std::vector<std::string> GetStringsFromData(Reader& aReader, const int acStringLength = 5)
{
  std::vector<std::string> strings{};

  char currentCharacter = '\00';
  constexpr size_t invalidPosition = std::numeric_limits<size_t>::max();
  size_t startPosition = invalidPosition;

  while (aReader.Read(currentCharacter))
  {
    if (isascii(currentCharacter))
    {
      if (IsEndOfStringChar(currentCharacter))
      {
        if (startPosition != invalidPosition
            && aReader.position - startPosition >= acStringLength)
        {
          aReader.position = startPosition;
          strings.push_back(std::move(aReader.ReadString()));
        }

        startPosition = invalidPosition;
      }
      else if (startPosition == invalidPosition)
        startPosition = aReader.position - 1;
    }
    else
      startPosition = invalidPosition;
  }

  return strings;
}

std::vector<std::string> GetStringsFromFile(const std::string& acFilename, const int acStringLength = 5)
{
  Reader reader{};
  if (!reader.LoadFromFile(acFilename))
  {
    spdlog::error("Failed to load to-parse file");
    return std::vector<std::string>{};
  }

  return GetStringsFromData(reader, acStringLength);
}

} // namespace Strings
