#pragma once

#include "Window.h"

class MenuWindow final : public Window
{
public:
  void Setup() override;
  void Update() override;

  void OnTestEvent(const Event& aEvent);

private:
  std::string openedFile{};
};
