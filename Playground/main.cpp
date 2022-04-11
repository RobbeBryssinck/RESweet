#include <REPair.h>
#include <RETree.h>

#include <spdlog/spdlog.h>
#include <spdlog/spdlog-inl.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

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

  REPair<int, float> pair(5, 6.f);
  spdlog::info("First: {}, second: {}", pair.first, pair.second);

  RETree<float> tree{};
  tree.Insert(5, 4.2f);
  tree.Insert(3, 6.8f);
  tree.Insert(8, 1.1f);
  const float* result = tree[5];
  if (result)
    spdlog::info("Result: {}", *result);
  else
    spdlog::error("Failed to fetch result");

  return 0;
}
