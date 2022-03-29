#pragma once

struct Event;

class Layer
{
public:
  virtual void Setup() = 0;
  virtual void UpdateLogic() = 0;
  virtual void UpdateUI() = 0;
  virtual void OnEvent(Event& event) = 0;
};
