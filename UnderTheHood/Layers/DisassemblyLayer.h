#pragma once

#include "Layer.h"

#include <BinLoader/Binary.h>

#include <cstdint>
#include <string>

struct cs_insn;

class DisassemblyLayer : public Layer
{
public:
  struct CapstoneOutput
  {
    bool DisassembleLinear(std::shared_ptr<Binary> apBinary);

    void Destroy();

    bool IsDisassembled() const { return instructions; }

    size_t handle = 0;
    size_t instructionCount = 0;
    cs_insn* instructions = nullptr;
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

