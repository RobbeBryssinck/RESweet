#pragma once

#include <string>
#include <vector>

namespace Strings
{

std::vector<std::string> GetStringsFromFile(const std::string& acFilename, const int acStringLength = 5);

} // namespace Strings
