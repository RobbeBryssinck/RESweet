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

  bool IsDisassembled() const { return !functions.empty(); }

  std::string BuildInstructionString(const cs_insn& apInstruction);

  void RenderDisassemblyModal(const Disassembly::Function& acFunction);

  void SaveToFile() const;
  void LoadFromFile(const std::string& acFilename);
  void Destroy();

  uint64_t count = 0;

  bool shouldDisassemble = false;
  bool shouldLoad = false;
  bool shouldSave = false;
  bool shouldClose = false;

  std::string fileToDisassemble = "";
  std::string fileToLoad = "";

  Disassembly::Function modalFunction{};
  Disassembly::Functions functions{};
};

