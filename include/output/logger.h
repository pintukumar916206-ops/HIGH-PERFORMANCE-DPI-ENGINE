#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <memory>

namespace packet_analyzer::output {

class Logger {
public:
    static void init(spdlog::level::level_enum level = spdlog::level::info) {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto logger = std::make_shared<spdlog::logger>("packet_analyzer", console_sink);
        spdlog::set_default_logger(logger);
        spdlog::set_level(level);
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
    }
};

} // namespace packet_analyzer::output
