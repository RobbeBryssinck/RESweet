#include <spdlog/spdlog.h>
#include <spdlog/spdlog-inl.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <iostream>

#include <BinLoader/BaseParser.h>
#include <ImGuiImpl/imgui_runner.h>

#include "Application.h"
#include "Disassembly/Disassembly.h"
#include "Layers/DisassemblyLayer.h"

void InitializeLogger()
{
  auto console = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  console->set_pattern("%^[%H:%M:%S] [%l]%$ %v");
  auto logger = std::make_shared<spdlog::logger>("", spdlog::sinks_init_list{ console });
  set_default_logger(logger);
}

int main(int argc, char* argv[])
{
  InitializeLogger();

  DisassemblyLayer layer;
  layer.Setup();

  Application application;
  application.AddLayer(&layer);
  application.Run();

  return 0;
}
