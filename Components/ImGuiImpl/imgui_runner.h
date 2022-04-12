#pragma once

#include <string>
#include <functional>

struct GLFWwindow;

class imgui_runner
{
public:
  imgui_runner(const std::string& acName);
  ~imgui_runner();
  imgui_runner(const imgui_runner&) = default;
  imgui_runner& operator=(const imgui_runner&) = default;

  bool BeginFrame();
  void EndFrame();

private:
  GLFWwindow* window{};
};
