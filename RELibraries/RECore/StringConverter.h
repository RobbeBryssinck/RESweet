#pragma once

#include <string>

namespace StringConverter
{
  std::string FromWide(const std::wstring& aFrom);
  std::wstring ToWide(const std::string& aFrom);
}
