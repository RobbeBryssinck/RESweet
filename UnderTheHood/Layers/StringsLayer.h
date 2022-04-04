#pragma once

#include "Layer.h"

class StringsLayer : public Layer
{
public:
  virtual void Setup() override;
  virtual void UpdateLogic() override;
  virtual void UpdateUI() override;
  virtual void OnEvent(const Event& acEvent) override;

private:
};
