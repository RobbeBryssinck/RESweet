#pragma once

#include "Layer.h"

#include <vector>
#include <string>

class StringsLayer : public Layer
{
public:
  virtual void Setup() override;
  virtual void UpdateLogic() override;
  virtual void UpdateUI() override;
  virtual void OnEvent(const Event& acEvent) override;

private:
  std::vector<std::string> strings{};

  bool shouldCollectStrings = false;
  std::string stringsFilename = "";
};
