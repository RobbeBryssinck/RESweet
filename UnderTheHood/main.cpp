#include <spdlog/spdlog.h>
#include <spdlog/spdlog-inl.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <BaseParser.h>

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
  spdlog::info("main()");

  std::shared_ptr<Binary> pBinary = Parsing::ParseFile("test.exe");
  spdlog::info("Binary name: {}, sections: {}, entry point is at 0x{:X}", pBinary->filename, pBinary->sections.size(), pBinary->entryPoint);

  return 0;
}
