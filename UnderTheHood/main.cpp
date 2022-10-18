#include <spdlog/spdlog.h>
#include <spdlog/spdlog-inl.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include <BinLoader/BaseParser.h>
#include <ImGuiImpl/imgui_runner.h>
#include <Writer.h>

#include "Application.h"
#include "Disassembly/Disassembly.h"
#include "Windows/DisassemblyWindow.h"
#include "Windows/StringsWindow.h"
#include "Windows/MenuWindow.h"
#include "Windows/AttacherWindow.h"

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

  Application application{};

  MenuWindow menuWindow{};
  application.AddWindow(&menuWindow);

  DisassemblyWindow disassemblyWindow{};
  application.AddWindow(&disassemblyWindow);

  StringsWindow stringsWindow{};
  application.AddWindow(&stringsWindow);

  AttacherWindow attacherWindow{};
  application.AddWindow(&attacherWindow);

  application.Run();

  return 0;
}
