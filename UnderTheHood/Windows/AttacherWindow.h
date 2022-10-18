#pragma once

#include "Window.h"

#include "../Events/Event.h"

#include <Processes.h>
#include <Debugger/Debugger.h>

#include <vector>
#include <string>

class AttacherWindow final : public Window
{
public:
  virtual void Setup() override;
  virtual void Update() override;
  virtual void SetShown(bool aShow) override;

  void OnOpen(const Event& aEvent);
  void OnClose(const Event& aEvent);

private:
  enum class UIError
  {
    kNone,
    kProcessListingFailed,
  };

  void RenderError();
  void RenderProcessListError();

  void InitListOfProcesses();

  void Destroy();

  Processes processes{};
  int currentProcess{};
  Debugger debugger{};
  bool isDebugging{};
  UIError currentUIError{ UIError::kNone };
};

