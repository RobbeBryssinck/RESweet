#include <spdlog/spdlog.h>
#include <spdlog/spdlog-inl.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <iostream>

#include <BinLoader/BaseParser.h>
#include <ImGuiImpl/imgui_runner.h>

#include "Disassembly/Disassembly.h"

void InitializeLogger()
{
  auto console = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  console->set_pattern("%^[%H:%M:%S] [%l]%$ %v");
  auto logger = std::make_shared<spdlog::logger>("", spdlog::sinks_init_list{ console });
  set_default_logger(logger);
}

#define RE_USE_DEFAULT_FILE

int main(int argc, char* argv[])
{
  InitializeLogger();

  Run();

  std::string file = "";

#ifndef RE_USE_DEFAULT_FILE
  std::cout << "What file would you like to disassemble?" << std::endl;
  std::cin >> file;
#endif

#ifdef RE_USE_DEFAULT_FILE
  file = "a.out";
#endif

  std::shared_ptr<Binary> pBinary = Parsing::ParseFile(std::move(file));
  if (!pBinary)
  {
    spdlog::error("Failed to load binary");
    return 1;
  }

  spdlog::info("Binary name: {}, sections: {}, entry point is at 0x{:X}", pBinary->filename, pBinary->sections.size(), pBinary->entryPoint);

  Disassembly::DisassembleLinear(pBinary);

  return 0;
}
