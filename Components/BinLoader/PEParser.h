#pragma once

#include <string>

class PEParser
{
	PEParser(const std::string& acFile);

	size_t size = 0;
	size_t position = 0;
	uint8_t* pBuffer = nullptr;
};
