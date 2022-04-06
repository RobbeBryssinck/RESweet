#pragma once

#include "Window.h"

#include <vector>
#include <string>

class StringsWindow : public Window
{
public:
  virtual void Setup() override;
  virtual void Update() override;
  virtual void OnEvent(const Event& acEvent) override;

private:
  std::vector<std::string> strings{};
};
