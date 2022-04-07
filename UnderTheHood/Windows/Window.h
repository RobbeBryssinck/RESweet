#pragma once

struct Event;

class Window
{
public:
  virtual ~Window() {};
  virtual void Setup() {};
  virtual void Update() {};
  virtual void OnEvent(const Event& acEvent) {};
};
