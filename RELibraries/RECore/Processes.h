#pragma once

#include <string>
#include <vector>
#include <optional>

using Processes = std::vector<std::pair<int, std::string>>;

std::optional<Processes> GetListOfProcesses();
