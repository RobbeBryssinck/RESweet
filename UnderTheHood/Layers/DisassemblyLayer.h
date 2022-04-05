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
  struct CapstoneOutput
  {
    struct Function
    {
      operator bool() const { return address != 0; }

      uint64_t address = 0;
      std::string name = "";
      size_t size = 0;
      std::vector<cs_insn> instructions{};
    };

    static std::string BuildInstructionString(const cs_insn* apInstruction);

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

  void RenderDisassemblyModal(const CapstoneOutput::Function& acFunction);

  uint64_t count = 0;

  bool shouldDisassemble = false;
  std::string fileToDisassemble = "";
  CapstoneOutput::Function modalFunction{};

  CapstoneOutput capstoneOutput{};
};

