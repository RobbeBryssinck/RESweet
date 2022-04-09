#pragma once

#include "Window.h"

#include "../Events/Event.h"

#include <vector>
#include <string>

class StringsWindow final : public Window
{
public:
  virtual void Setup() override;
  virtual void Update() override;

  void OnOpenFile(const Event& aEvent);

private:
  std::vector<std::string> strings{};
};
