#pragma once

#include "../Events/Event.h"

class Window
{
public:
  virtual ~Window() {};
  virtual void Setup() {};
  virtual void Update() {};
  virtual void SetShown(bool aShow) { shown = aShow; }

  void ToggleWindowShown()
  {
    SetShown(!shown);
  }

protected:
  bool shown{ true };
};
