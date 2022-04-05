#include <spdlog/spdlog.h>
#include <spdlog/spdlog-inl.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include <BinLoader/BaseParser.h>
#include <ImGuiImpl/imgui_runner.h>
#include <Writer.h>

#include "Application.h"
#include "Disassembly/Disassembly.h"
#include "Layers/DisassemblyLayer.h"
#include "Layers/StringsLayer.h"

void InitializeLogger()
{
  auto console = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  console->set_pattern("%^[%H:%M:%S] [%l]%$ %v");
  auto logger = std::make_shared<spdlog::logger>("", spdlog::sinks_init_list{ console });
  //logger->set_level(spdlog::level::debug);
  set_default_logger(logger);
}

int main(int argc, char* argv[])
{
  InitializeLogger();

  std::string str1 = "Hello";
  std::string str2 = "Good morning";

  Writer writer{};
  writer.WriteImpl((void*)str1.c_str(), str1.size());
  writer.WriteImpl((void*)str2.c_str(), str2.size());

  DisassemblyLayer disassemblyLayer;
  disassemblyLayer.Setup();

  StringsLayer stringsLayer;
  stringsLayer.Setup();

  Application application;
  application.AddLayer(&disassemblyLayer);
  application.AddLayer(&stringsLayer);
  application.Run();

  return 0;
}
