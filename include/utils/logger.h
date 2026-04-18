#pragma once

#include <iostream>
#include <string>
#include "compat.h"

namespace utils {

class Logger {
public:
    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    template<typename T>
    void logInfo(const T& msg) {
        compat::lock_guard<compat::mutex> lock(mu_);
        std::cout << "info: " << msg << "\n";
    }

    template<typename T>
    void logError(const T& msg) {
        compat::lock_guard<compat::mutex> lock(mu_);
        std::cerr << "error: " << msg << "\n";
    }

    template<typename T>
    void logWarn(const T& msg) {
        compat::lock_guard<compat::mutex> lock(mu_);
        std::cout << "warn: " << msg << "\n";
    }

private:
    Logger() = default;
    compat::mutex mu_;
};

}

#define LOG_INFO(msg)  ::utils::Logger::instance().logInfo(msg)
#define LOG_WARN(msg)  ::utils::Logger::instance().logWarn(msg)
#define LOG_ERROR(msg) ::utils::Logger::instance().logError(msg)
