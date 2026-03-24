#ifndef COMPAT_H
#define COMPAT_H

#if defined(_WIN32)
    #undef _WIN32_WINNT
    #define _WIN32_WINNT 0x0600
#endif

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <stdexcept>
#include <functional>

// --- SHARED FALLBACK SHIMS ---

namespace compat_internal {
    struct nullopt_t {
        explicit constexpr nullopt_t(int) {}
    };
    static constexpr nullopt_t nullopt{0};

    template<typename T>
    class optional_shim {
    private:
        T* v_ptr;
        bool has_;
        uint8_t storage[sizeof(T)];
    public:
        optional_shim() : v_ptr(nullptr), has_(false) {}
        optional_shim(nullopt_t) : v_ptr(nullptr), has_(false) {}
        optional_shim(const T& v) : has_(true) { v_ptr = new(&storage) T(v); }
        optional_shim(const optional_shim& other) : has_(other.has_) {
            if (has_) v_ptr = new(&storage) T(*other.v_ptr);
            else v_ptr = nullptr;
        }
        ~optional_shim() { if (has_) v_ptr->~T(); }
        bool has_value() const { return has_; }
        explicit operator bool() const { return has_; }
        T& value_or(const T& def) { return has_ ? *v_ptr : def; }
        T& operator*() { return *v_ptr; }
        const T& operator*() const { return *v_ptr; }
        T* operator->() { return v_ptr; }
    };

    class string_view_shim {
    private:
        const char* str_;
        size_t len_;
    public:
        static constexpr size_t npos = static_cast<size_t>(-1);
        string_view_shim() : str_(nullptr), len_(0) {}
        string_view_shim(const char* s) : str_(s), len_(s ? std::string(s).length() : 0) {}
        string_view_shim(const std::string& s) : str_(s.data()), len_(s.length()) {}
        string_view_shim(const char* s, size_t len) : str_(s), len_(len) {}
        const char* data() const { return str_; }
        size_t size() const { return len_; }
        size_t length() const { return len_; }
        bool empty() const { return len_ == 0; }
        char operator[](size_t i) const { return str_[i]; }
        operator std::string() const { return (str_ && len_ > 0) ? std::string(str_, len_) : std::string(); }
        size_t find(char c, size_t pos = 0) const {
            if (pos >= len_) return npos;
            for (size_t i = pos; i < len_; ++i) if (str_[i] == c) return i;
            return npos;
        }
        size_t find(const char* s, size_t pos = 0) const {
            if (!s || pos >= len_) return npos;
            std::string fs(str_, len_);
            size_t r = fs.find(s, pos);
            return (r == std::string::npos) ? npos : r;
        }
        string_view_shim substr(size_t pos, size_t count = npos) const {
            if (pos > len_) return string_view_shim();
            size_t rc = (count == npos || pos + count > len_) ? len_ - pos : count;
            return string_view_shim(str_ + pos, rc);
        }
    };
}

// --- PLATFORM SELECTION ---

#if defined(_WIN32) && (!defined(__GNUC__) || (__GNUC__ < 8))
    #include <windows.h>
    #include <process.h>

    namespace compat {
        class mutex {
            CRITICAL_SECTION cs;
        public:
            mutex() { InitializeCriticalSection(&cs); }
            ~mutex() { DeleteCriticalSection(&cs); }
            void lock() { EnterCriticalSection(&cs); }
            void unlock() { LeaveCriticalSection(&cs); }
            CRITICAL_SECTION* native_handle() { return &cs; }
        };

        template<typename M>
        class unique_lock {
            M& m_; bool l_;
        public:
            explicit unique_lock(M& m) : m_(m), l_(true) { m_.lock(); }
            ~unique_lock() { if (l_) m_.unlock(); }
            void lock() { if (!l_) { m_.lock(); l_ = true; } }
            void unlock() { if (l_) { m_.unlock(); l_ = false; } }
            M& mutex() { return m_; }
        };

        template<typename M>
        struct lock_guard {
            M& m_;
            explicit lock_guard(M& m) : m_(m) { m_.lock(); }
            ~lock_guard() { m_.unlock(); }
        };

        class condition_variable {
            CONDITION_VARIABLE cv;
        public:
            condition_variable() { InitializeConditionVariable(&cv); }
            void notify_one() { WakeConditionVariable(&cv); }
            void notify_all() { WakeAllConditionVariable(&cv); }
            
            template<typename LockType>
            void wait(LockType& lk) {
                SleepConditionVariableCS(&cv, lk.mutex().native_handle(), INFINITE);
            }

            template<typename LockType, typename Predicate>
            void wait(LockType& lk, Predicate pred) {
                while (!pred()) {
                    wait(lk);
                }
            }
        };

        inline unsigned __stdcall thread_entry(void* p) {
            auto* fn = static_cast<std::function<void()>*>(p);
            (*fn)();
            delete fn;
            return 0;
        }

        class thread {
            HANDLE h;
        public:
            thread() : h(NULL) {}
            template<typename F>
            explicit thread(F f) {
                auto* p = new std::function<void()>(f);
                h = (HANDLE)_beginthreadex(NULL, 0, thread_entry, p, 0, NULL);
            }
            void join() { if (h) { WaitForSingleObject(h, INFINITE); CloseHandle(h); h = NULL; } }
            bool joinable() const { return h != NULL; }
            ~thread() { if (h) CloseHandle(h); }
        };

        inline void sleep_ms(uint32_t ms) { Sleep(ms); }

        using string_view = compat_internal::string_view_shim;
        template<typename T> using optional = compat_internal::optional_shim<T>;
        using nullopt_t = compat_internal::nullopt_t;
        static constexpr nullopt_t nullopt = compat_internal::nullopt;
    }
#else
    #include <mutex>
    #include <thread>
    #include <condition_variable>
    #if __cplusplus >= 201703L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
        #include <string_view>
        #include <optional>
    #endif

    namespace compat {
        using mutex = std::mutex;
        template<typename T> using unique_lock = std::unique_lock<T>;
        template<typename T> using lock_guard = std::lock_guard<T>;
        using condition_variable = std::condition_variable;
        using thread = std::thread;

        #if __cplusplus >= 201703L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
            using string_view = std::string_view;
            template<typename T> using optional = std::optional<T>;
            using nullopt_t = std::nullopt_t;
            using std::nullopt;
        #else
            using string_view = compat_internal::string_view_shim;
            template<typename T> using optional = compat_internal::optional_shim<T>;
            using nullopt_t = compat_internal::nullopt_t;
            static constexpr nullopt_t nullopt = compat_internal::nullopt;
        #endif

        inline void sleep_ms(uint32_t ms) {
            std::this_thread::sleep_for(std::chrono::milliseconds(ms));
        }
    }
#endif

#endif
