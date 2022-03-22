#include "PEParser.h"

#include <filesystem>
#include <fstream>

PEParser::PEParser(const std::string& acFile)
{
	size = std::filesystem::file_size(acFile);

	std::ifstream file(acFile, std::ios::binary);
	if (file.fail())
	{
		// TODO: log error
		return;
	}

	file.read(reinterpret_cast<char*>(pBuffer), size);
}
