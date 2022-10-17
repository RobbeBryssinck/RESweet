#include "DebuggerWindow.h"

#include "../Application.h"

#include <imgui.h>
#include <spdlog/spdlog.h>

#include <Processes.h>

void DebuggerWindow::Setup()
{
  Application::Get().GetDispatcher().Subscribe(Event::Type::kOpenFile, std::bind(&DebuggerWindow::OnOpen, this, std::placeholders::_1));
  Application::Get().GetDispatcher().Subscribe(Event::Type::kLoad, std::bind(&DebuggerWindow::OnOpen, this, std::placeholders::_1));
  Application::Get().GetDispatcher().Subscribe(Event::Type::kClose, std::bind(&DebuggerWindow::OnClose, this, std::placeholders::_1));
}

void DebuggerWindow::Update()
{
  if (!isLoaded)
    return;

  ImGui::Begin("Debugger");

  RenderError();

  if (ImGui::Button("Refresh list of processes"))
    InitListOfProcesses();

  if (!processes.empty() && !isDebugging)
  {
    std::unique_ptr<const char* []> items = std::make_unique<const char* []>(processes.size());
    for (int i = 0; i < processes.size(); i++)
      items[i] = processes[i].second.c_str();

    ImGui::PushItemWidth(-1);
    ImGui::ListBox("Processes", &currentProcess, items.get(), processes.size(), 20);
    ImGui::PopItemWidth();

    if (ImGui::Button("Debug"))
      isDebugging = debugger.AttachDebugger(processes[currentProcess].first);
  }
  else if (isDebugging)
  {
    const auto isDebugging = fmt::format("Is debugging? {}", debugger.IsDebugging());
    ImGui::Text(isDebugging.c_str());
  }

  ImGui::End();
}

void DebuggerWindow::OnOpen(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kOpenFile || aEvent.GetType() == Event::Type::kLoad);

  isLoaded = true;
  InitListOfProcesses();
}

void DebuggerWindow::OnClose(const Event& aEvent)
{
  RE_ASSERT(aEvent.GetType() == Event::Type::kClose);

  isLoaded = false;
  processes.clear();
  currentProcess = 1;
  isDebugging = false;
}

void DebuggerWindow::RenderError()
{
  switch (currentUIError)
  {
  case UIError::kProcessListingFailed:
    RenderProcessListError();
    break;
  case UIError::kNone:
    break;
  }
}

void DebuggerWindow::RenderProcessListError()
{
  ImVec2 center = ImGui::GetMainViewport()->GetCenter();
  ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

  if (ImGui::BeginPopupModal("Process list failed", NULL, ImGuiWindowFlags_AlwaysAutoResize))
  {
    ImGui::Text("Failed to load process list.");

    if (ImGui::Button("Close"))
    {
      currentUIError = UIError::kNone;
      ImGui::CloseCurrentPopup();
    }

    ImGui::EndPopup();
  }
}

void DebuggerWindow::InitListOfProcesses()
{
  currentProcess = 1;

  auto result = GetListOfProcesses();
  if (!result)
    currentUIError = UIError::kProcessListingFailed;
  else
  {
    processes = *result;
    for (auto& process : processes)
      process.second = fmt::format("{} {}", process.first, process.second);
  }
}
