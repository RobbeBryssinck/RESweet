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
  void OnSave(const Event& aEvent);

private:
  void Save() const;

  std::vector<std::string> strings{};
};
