#pragma once

#include "Layer.h"

#include <cstdint>

class DisassemblyLayer : public Layer
{
public:
  virtual void Setup() override;
  virtual void UpdateLogic() override;
  virtual void UpdateUI() override;
  virtual void OnEvent(const Event& acEvent) override;

private:
  uint64_t count = 0;
};

