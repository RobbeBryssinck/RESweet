#pragma once

#include <BinLoader/Binary.h>
#include <memory>

namespace Disassembly
{

bool DisassembleLinear(std::shared_ptr<Binary> apBinary);

} // namespace Disassembly
