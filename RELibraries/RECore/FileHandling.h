#pragma once

#include <string>
#include <vector>

using FileFilters = std::vector<std::pair<std::string, std::string>>;

std::string OpenFileDialogue(const std::string* apcDialogueName = nullptr, FileFilters* apcFilters = nullptr);
