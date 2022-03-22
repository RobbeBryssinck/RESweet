#include <spdlog/spdlog.h>
#include <spdlog/spdlog-inl.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <PEParser.h>

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

  PEParser parser("test.exe");
  parser.Parse();
  return 0;
}
