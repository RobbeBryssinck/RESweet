#pragma once

#include <Binary.h>

#include <capstone/capstone.h>

#include <vector>
#include <string>
#include <unordered_map>

namespace Disassembly
{

struct Function
{
  operator bool() const { return address != 0; }

  uint64_t address = 0;
  std::string name = "";
  size_t size = 0;
  // TODO: own version of cs_insn to break capstone dependency in header?
  std::vector<cs_insn> instructions{};
};

using Functions = std::unordered_map<uint64_t, Function>;

Functions Disassemble(std::shared_ptr<Binary> apBinary, const bool aRecursive = true);

} // namespace Disassembly
