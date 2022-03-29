#pragma once

// TODO: event system (or observer system?)
struct Event;

class Application
{
public:
  Application();

  [[nodiscard]] static Application& Get() { return *s_application; }

  void Run();
  void OnEvent(const Event& acEvent);
  
private:
  static Application* s_application;

  bool isRunning = true;
};
