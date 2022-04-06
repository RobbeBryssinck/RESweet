#pragma once

struct Event;

class Window
{
public:
  virtual void Setup() {};
  virtual void UpdateLogic() {};
  virtual void UpdateUI() {};
  virtual void OnEvent(const Event& acEvent) {};
};
