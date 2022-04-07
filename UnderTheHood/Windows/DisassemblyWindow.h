#pragma once

#include "Window.h"

#include <Disassembly/Disassembly.h>

#include <cstdint>
#include <string>
#include <unordered_map>

class DisassemblyWindow : public Window
{
public:
  DisassemblyWindow() = default;
  ~DisassemblyWindow();
  DisassemblyWindow(const DisassemblyWindow&) = default;
  DisassemblyWindow& operator=(const DisassemblyWindow&) = default;

  virtual void Setup() override;
  virtual void Update() override;
  virtual void OnEvent(const Event& acEvent) override;

private:

  bool IsDisassembled() const noexcept { return !functions.empty(); }

  std::string BuildInstructionString(const cs_insn& apInstruction);

  void RenderDisassemblyModal(const Disassembly::Function& acFunction);

  void SaveToFile() const;
  void LoadFromFile(const std::string& acFilename);
  void Destroy();

  uint64_t count = 0;

  std::string fileToDisassemble = "";

  Disassembly::Function modalFunction{};
  Disassembly::Functions functions{};
};

