#pragma once

#include "Layer.h"

#include <BinLoader/Binary.h>

#include <capstone/capstone.h>

#include <cstdint>
#include <string>
#include <unordered_map>

class DisassemblyLayer : public Layer
{
public:
  // TODO: move the disassembly to its own component
  struct CapstoneOutput
  {
    struct Function
    {
      uint64_t address = 0;
      size_t size = 0;
      std::vector<cs_insn> instructions{};
    };

    static void PrintInstruction(cs_insn* apInstruction);

  private:
    bool SetupDisassembly(std::shared_ptr<Binary> apBinary);
    bool IsControlInstruction(uint8_t aInstruction) const;
    bool IsEndOfFunction(cs_insn* apInstruction, size_t aSize, uint64_t aAddress, const uint8_t* apData);

  public:
    bool DisassembleLinear(std::shared_ptr<Binary> apBinary);
    bool DisassembleRecursive(std::shared_ptr<Binary> apBinary);

    void Destroy();

    bool IsDisassembled() const { return handle; }

    size_t handle = 0;
    size_t instructionCount = 0;
    cs_insn* instructions = nullptr;
    std::unordered_map<uint64_t, Function> functions{};
  };

  DisassemblyLayer() = default;
  ~DisassemblyLayer();

  virtual void Setup() override;
  virtual void UpdateLogic() override;
  virtual void UpdateUI() override;
  virtual void OnEvent(const Event& acEvent) override;

private:
  uint64_t count = 0;

  bool shouldDisassemble = false;
  std::string fileToDisassemble = "";

  CapstoneOutput capstoneOutput{};
};

