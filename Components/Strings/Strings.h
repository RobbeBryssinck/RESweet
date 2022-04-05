#pragma once

#include <Reader.h>

#include <spdlog/spdlog.h>

#include <string>
#include <vector>
#include <ctype.h>

namespace Strings
{

std::vector<std::string> GetStringsFromData(Reader& aReader, const int acMinStringLength = 5)
{
  std::vector<std::string> strings{};

  char currentCharacter = '\00';
  constexpr size_t invalidPosition = std::numeric_limits<size_t>::max();
  size_t startPosition = invalidPosition;

  while (aReader.Read(currentCharacter))
  {
    if (isascii(currentCharacter))
    {
      if (currentCharacter == '\00')
      {
        if (startPosition != invalidPosition
            && aReader.position - startPosition >= (acMinStringLength + 1)) // +1 to min string length to account for null byte
        {
          aReader.position = startPosition;
          strings.push_back(std::move(aReader.ReadString()));
          spdlog::debug("String at position {:X}: {}", startPosition, strings.back());
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
