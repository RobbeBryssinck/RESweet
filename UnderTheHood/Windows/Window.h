#pragma once

#include "../Events/Event.h"

class Window
{
public:
  virtual ~Window() {};
  virtual void Setup() {};
  virtual void Update() {};
};
