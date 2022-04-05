#pragma once

#include "Layer.h"

#include <Disassembly/Disassembly.h>

#include <cstdint>
#include <string>
#include <unordered_map>

class DisassemblyLayer : public Layer
{
public:
  DisassemblyLayer() = default;
  ~DisassemblyLayer();

  virtual void Setup() override;
  virtual void UpdateLogic() override;
  virtual void UpdateUI() override;
  virtual void OnEvent(const Event& acEvent) override;

private:

  std::string BuildInstructionString(const cs_insn& apInstruction);

  void RenderDisassemblyModal(const Disassembly::Function& acFunction);

  uint64_t count = 0;

  bool shouldDisassemble = false;
  std::string fileToDisassemble = "";
  Disassembly::Function modalFunction{};

  Disassembly::Functions functions{};
};

