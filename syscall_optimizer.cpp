/**
 * syscall_optimizer.cpp
 *
 * Полный анализатор 10 категорий анти-паттернов системных вызовов на macOS.
 *
 * Категории анти-паттернов:
 * 1.  [UNBUFFERED_IO]        Небуферизованный В/В (побайтовые read/write)
 * 2.  [MEMORY_THRASHING]     Частое выделение виртуальной памяти (mmap/munmap/mprotect)
 * 3.  [STAT_SPAM]            Спам метаданными файлов (stat/fstatat/getattrlist)
 * 4.  [TIME_POLLING]         Активный опрос времени и короткие таймеры (clock_gettime/nanosleep)
 * 5.  [THREAD_SPAM]          Спам созданием сырых потоков (pthread_create/bsdthread_create)
 * 6.  [SOCKET_RECONNECT_SPAM]Пересоздание сокетов на каждый запрос (socket/connect/close)
 * 7.  [LOCK_CONTENTION]      Блокировки ядра и контеншн (ulock_wait/semwait)
 * 8.  [PROCESS_FORK_SPAM]    Частый спавн дочерних процессов (fork/execve)
 * 9.  [FD_CHURN]             Частые переоткрытия дескрипторов файлов (open/close)
 * 10. [SIGNAL_SPAM]          Сигналы управления потоком (kill/pthread_kill/sigprocmask)
 *
 * Сборка:
 *   clang++ -std=c++17 -O2 -o syscall_optimizer syscall_optimizer.cpp -ldtrace
 *
 * Запуск (нужен root):
 *   sudo ./syscall_optimizer [--json | --markdown | --report] <program> [args...]
 */

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <cerrno>
#include <atomic>
#include <chrono>

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <dtrace.h>

enum class OutputFormat {
    REPORT,     // Подробный текстовый отчет с рекомендациями
    MARKDOWN,   // Формат Markdown для LLM
    JSON        // Формат JSON для автоматического анализа в CI/CD и LLM
};

struct SyscallStats {
    std::string name;
    uint64_t count = 0;
    std::unordered_map<std::string, uint64_t> call_stacks;
};

struct AntiPatternIssue {
    std::string rule_id;       // Идентификатор правила
    std::string title;         // Название проблемы
    std::string description;   // Детальное описание
    std::string recommendation;// Конкретное решение
    uint64_t impact_count = 0; // Потенциал экономии сисколов
    std::string top_stack;     // Стековый кадр из вызова
};

static dtrace_hdl_t*     g_dtp    = nullptr;
static pid_t             g_target = -1;
static std::atomic<bool> g_done{false};

static std::unordered_map<std::string, SyscallStats> g_stats;
static std::unordered_map<uint64_t, std::string>     g_symbol_cache;

static const char* D_SCRIPT_TEMPLATE = R"(
syscall:::entry
/pid == %d/
{
    @[probefunc, ustack(12)] = count();
}
)";

static void sig_handler(int) {
    g_done.store(true, std::memory_order_relaxed);
}

static int dtrace_err_cb(const dtrace_errdata_t* data, void*) {
    std::cerr << "[dtrace error] " << data->dteda_msg << "\n";
    return DTRACE_HANDLE_OK;
}

static std::string strip_symbol_offset(const std::string& raw_sym) {
    size_t plus_pos = raw_sym.rfind('+');
    if (plus_pos != std::string::npos && plus_pos > 0) {
        std::string suffix = raw_sym.substr(plus_pos + 1);
        if (!suffix.empty() && (suffix.rfind("0x", 0) == 0 || std::isdigit(suffix[0]))) {
            return raw_sym.substr(0, plus_pos);
        }
    }
    return raw_sym;
}

static const std::string& resolve_pc_symbol(uint64_t pc) {
    auto it = g_symbol_cache.find(pc);
    if (it != g_symbol_cache.end()) return it->second;

    char symbuf[1024];
    std::string symbol_str;
    if (dtrace_addr2str(g_dtp, pc, symbuf, sizeof(symbuf)) == 0) {
        symbol_str = strip_symbol_offset(symbuf);
    } else {
        std::stringstream ss;
        ss << "0x" << std::hex << pc;
        symbol_str = ss.str();
    }

    auto [new_it, _] = g_symbol_cache.emplace(pc, std::move(symbol_str));
    return new_it->second;
}

static int aggwalk_cb(const dtrace_aggdata_t* data, void*) {
    const dtrace_aggdesc_t* agg = data->dtada_desc;
    if (agg->dtagd_nrecs < 3) return DTRACE_AGGWALK_NEXT;

    const dtrace_recdesc_t* rec_syscall = &agg->dtagd_rec[1];
    const char* syscall_name = data->dtada_data + rec_syscall->dtrd_offset;

    const dtrace_recdesc_t* val_rec = &agg->dtagd_rec[agg->dtagd_nrecs - 1];
    uint64_t count = 0;
    std::memcpy(&count, data->dtada_data + val_rec->dtrd_offset, sizeof(uint64_t));

    const dtrace_recdesc_t* rec_stack = &agg->dtagd_rec[2];
    caddr_t stack_buf = data->dtada_data + rec_stack->dtrd_offset;
    uint32_t num_frames = rec_stack->dtrd_size / sizeof(uint64_t);
    const uint64_t* pc_addrs = reinterpret_cast<const uint64_t*>(stack_buf);

    std::string stack_str;
    for (uint32_t i = 0; i < num_frames; ++i) {
        uint64_t pc = pc_addrs[i];
        if (pc == 0) break;
        if (!stack_str.empty()) stack_str += " -> ";
        stack_str += resolve_pc_symbol(pc);
    }

    if (syscall_name && syscall_name[0] != '\0') {
        std::string sys_str = syscall_name;
        auto& stat = g_stats[sys_str];
        stat.name = sys_str;
        stat.count += count;
        if (!stack_str.empty()) {
            stat.call_stacks[stack_str] += count;
        }
    }

    return DTRACE_AGGWALK_NEXT;
}

// ─────────────────────────────────────────────────────────────────────────────
// Детектор 10 категорий анти-паттернов системных вызовов
// ─────────────────────────────────────────────────────────────────────────────

static std::vector<AntiPatternIssue> analyze_anti_patterns(uint64_t& total_syscalls) {
    std::vector<AntiPatternIssue> issues;
    total_syscalls = 0;

    for (const auto& [name, stat] : g_stats) {
        total_syscalls += stat.count;
    }

    if (total_syscalls == 0) return issues;

    // Вспомогательная функция поиска стека с максимальным числом вызовов
    auto find_top_stack = [](const std::vector<std::string>& keywords) -> std::pair<uint64_t, std::string> {
        uint64_t total = 0;
        uint64_t max_cnt = 0;
        std::string top_stk;

        for (const auto& [name, stat] : g_stats) {
            for (const auto& kw : keywords) {
                if (name.find(kw) != std::string::npos) {
                    total += stat.count;
                    for (const auto& [stk, cnt] : stat.call_stacks) {
                        if (cnt > max_cnt) {
                            max_cnt = cnt;
                            top_stk = stk;
                        }
                    }
                    break;
                }
            }
        }
        return {total, top_stk};
    };

    // 1. UNBUFFERED_IO
    auto [io_calls, io_stack] = find_top_stack({"read", "write"});
    if (io_calls >= 20 && (io_calls * 100.0 / total_syscalls) > 25.0) {
        AntiPatternIssue issue;
        issue.rule_id = "UNBUFFERED_IO";
        issue.title = "Избыточный / Небуферизованный Ввод-Вывод (Unbuffered I/O Loop)";
        issue.description = "Зафиксировано " + std::to_string(io_calls) + " мелких вызовов чтения/записи (" + 
                            std::to_string((int)(io_calls * 100.0 / total_syscalls)) + "% всех вызовов ядра).";
        issue.recommendation = "Накапливайте данные в буфере памяти (std::vector<char>, fstream, MemoryStream) и делайте запись пачкой за один вызов write().";
        issue.impact_count = io_calls > 5 ? (io_calls - 5) : io_calls;
        issue.top_stack = io_stack;
        issues.push_back(issue);
    }

    // 2. MEMORY_THRASHING
    auto [mem_calls, mem_stack] = find_top_stack({"mmap", "munmap", "mprotect", "madvise"});
    if (mem_calls >= 15 && (mem_calls * 100.0 / total_syscalls) > 20.0) {
        AntiPatternIssue issue;
        issue.rule_id = "MEMORY_THRASHING";
        issue.title = "Частые запросы к подсистеме виртуальной памяти (Memory Thrashing)";
        issue.description = "Зафиксировано " + std::to_string(mem_calls) + " вызовов выделения/освобождения страниц ядра (mmap/munmap/mprotect).";
        issue.recommendation = "Используйте Арена-Аллокатор (Arena / Memory Pool Allocator) или переиспользуйте выделенные массивы вместо частых запросов к ОС.";
        issue.impact_count = mem_calls > 3 ? (mem_calls - 3) : mem_calls;
        issue.top_stack = mem_stack;
        issues.push_back(issue);
    }

    // 3. STAT_SPAM
    auto [stat_calls, stat_stack] = find_top_stack({"stat", "getattr"});
    if (stat_calls >= 15 && (stat_calls * 100.0 / total_syscalls) > 15.0) {
        AntiPatternIssue issue;
        issue.rule_id = "STAT_SPAM";
        issue.title = "Спам запросами метаданных файлов (VFS Stat Overhead)";
        issue.description = "Зафиксировано " + std::to_string(stat_calls) + " вызовов проверки атрибутов файлов (stat/fstatat/getattrlist).";
        issue.recommendation = "Кешируйте атрибуты файлов в оперативной памяти или опрашивайте структуру директории единым проходом.";
        issue.impact_count = stat_calls > 3 ? (stat_calls - 3) : stat_calls;
        issue.top_stack = stat_stack;
        issues.push_back(issue);
    }

    // 4. TIME_POLLING
    auto [time_calls, time_stack] = find_top_stack({"time", "sleep", "select", "kevent", "poll"});
    if (time_calls >= 20 && (time_calls * 100.0 / total_syscalls) > 20.0) {
        AntiPatternIssue issue;
        issue.rule_id = "TIME_POLLING";
        issue.title = "Активное ожидание и частый опрос времени (Busy Wait / Time Polling)";
        issue.description = "Зафиксировано " + std::to_string(time_calls) + " вызовов запроса времени или таймеров.";
        issue.recommendation = "Перейдите на Event-Driven модель (Condition Variable, epoll/kevent) вместо циклов активного ожидания.";
        issue.impact_count = time_calls > 5 ? (time_calls - 5) : time_calls;
        issue.top_stack = time_stack;
        issues.push_back(issue);
    }

    // 5. THREAD_SPAM
    auto [thread_calls, thread_stack] = find_top_stack({"bsdthread_create", "pthread_create", "workq"});
    if (thread_calls >= 10) {
        AntiPatternIssue issue;
        issue.rule_id = "THREAD_SPAM";
        issue.title = "Избыточное создание сырых потоков (Thread Creation Overhead)";
        issue.description = "Зафиксировано " + std::to_string(thread_calls) + " системных вызовов порождения потоков ядра.";
        issue.recommendation = "Используйте Пул потоков (Thread Pool / Task Scheduler) вместо создания и уничтожения сырых ОС-потоков на каждую задачу.";
        issue.impact_count = thread_calls > 2 ? (thread_calls - 2) : thread_calls;
        issue.top_stack = thread_stack;
        issues.push_back(issue);
    }

    // 6. SOCKET_RECONNECT_SPAM
    auto [sock_calls, sock_stack] = find_top_stack({"connect", "bind", "listen"});
    if (sock_calls >= 10) {
        AntiPatternIssue issue;
        issue.rule_id = "SOCKET_RECONNECT_SPAM";
        issue.title = "Пересоздание сетевых соединений (Socket Thrashing)";
        issue.description = "Зафиксировано " + std::to_string(sock_calls) + " вызовов установления сетевых соединений.";
        issue.recommendation = "Используйте Socket Connection Pool или HTTP Keep-Alive для постоянного переиспользования открытых соединений.";
        issue.impact_count = sock_calls > 2 ? (sock_calls - 2) : sock_calls;
        issue.top_stack = sock_stack;
        issues.push_back(issue);
    }

    // 7. LOCK_CONTENTION
    auto [lock_calls, lock_stack] = find_top_stack({"ulock_wait", "semwait", "mutex"});
    if (lock_calls >= 15) {
        AntiPatternIssue issue;
        issue.rule_id = "LOCK_CONTENTION";
        issue.title = "Контеншн и блокировки ядра (Kernel Lock Contention)";
        issue.description = "Зафиксировано " + std::to_string(lock_calls) + " вызовов перехода потока в состояние ожидания ядра.";
        issue.recommendation = "Уменьшите гранулярность мьютексов, перейдите на Lock-Free структуры данных или Атомики (std::atomic, MPMC queue).";
        issue.impact_count = lock_calls > 3 ? (lock_calls - 3) : lock_calls;
        issue.top_stack = lock_stack;
        issues.push_back(issue);
    }

    // 8. PROCESS_FORK_SPAM
    auto [fork_calls, fork_stack] = find_top_stack({"fork", "vfork", "execve"});
    if (fork_calls >= 5) {
        AntiPatternIssue issue;
        issue.rule_id = "PROCESS_FORK_SPAM";
        issue.title = "Частый спавн дочерних процессов (Process Fork Overhead)";
        issue.description = "Зафиксировано " + std::to_string(fork_calls) + " тяжелых вызовов создания дочерних процессов OS.";
        issue.recommendation = "Выполняйте код внутри текущего процесса через библиотеки / worker-демоны вместо спавна новых процессов.";
        issue.impact_count = fork_calls > 1 ? (fork_calls - 1) : fork_calls;
        issue.top_stack = fork_stack;
        issues.push_back(issue);
    }

    // 9. FD_CHURN
    auto [fd_calls, fd_stack] = find_top_stack({"open", "close"});
    if (fd_calls >= 30 && (fd_calls * 100.0 / total_syscalls) > 25.0) {
        AntiPatternIssue issue;
        issue.rule_id = "FD_CHURN";
        issue.title = "Частое переоткрытие дескрипторов файлов (Descriptor Churn)";
        issue.description = "Зафиксировано " + std::to_string(fd_calls) + " вызовов открытия/закрытия файлов.";
        issue.recommendation = "Удерживайте открытые файловые дескрипторы для частых операций вместо постоянного цикла open() / close().";
        issue.impact_count = fd_calls > 5 ? (fd_calls - 5) : fd_calls;
        issue.top_stack = fd_stack;
        issues.push_back(issue);
    }

    // 10. SIGNAL_SPAM
    auto [sig_calls, sig_stack] = find_top_stack({"kill", "sigprocmask", "pthread_kill"});
    if (sig_calls >= 10) {
        AntiPatternIssue issue;
        issue.rule_id = "SIGNAL_SPAM";
        issue.title = "Избыточная межпроцессная сигнализация (Signal Overhead)";
        issue.description = "Зафиксировано " + std::to_string(sig_calls) + " вызовов отправки и маскирования сигналов ОС.";
        issue.recommendation = "Используйте атомарные флаги или каналы обмена сообщениями вместо межпотоковых сигналов.";
        issue.impact_count = sig_calls > 2 ? (sig_calls - 2) : sig_calls;
        issue.top_stack = sig_stack;
        issues.push_back(issue);
    }

    return issues;
}

// ─────────────────────────────────────────────────────────────────────────────
// Вывод результатов
// ─────────────────────────────────────────────────────────────────────────────

static std::string json_escape(const std::string& s) {
    std::string res;
    res.reserve(s.size() + 16);
    for (char c : s) {
        if (c == '"') res += "\\\"";
        else if (c == '\\') res += "\\\\";
        else res += c;
    }
    return res;
}

static void render_output(OutputFormat format, const std::string& target_cmd) {
    uint64_t total_syscalls = 0;
    auto issues = analyze_anti_patterns(total_syscalls);

    uint64_t potential_savings = 0;
    for (const auto& issue : issues) {
        potential_savings += issue.impact_count;
    }

    double efficiency_score = 100.0;
    if (total_syscalls > 0) {
        double penalty = (potential_savings * 100.0) / total_syscalls;
        efficiency_score = std::max(0.0, 100.0 - penalty);
    }

    if (format == OutputFormat::JSON) {
        std::cout << "{\n";
        std::cout << "  \"target\": \"" << json_escape(target_cmd) << "\",\n";
        std::cout << "  \"pid\": " << g_target << ",\n";
        std::cout << "  \"total_syscalls\": " << total_syscalls << ",\n";
        std::cout << "  \"potential_syscalls_saved\": " << potential_savings << ",\n";
        std::cout << "  \"efficiency_score\": " << std::fixed << std::setprecision(1) << efficiency_score << ",\n";
        std::cout << "  \"issues\": [\n";

        for (size_t i = 0; i < issues.size(); ++i) {
            const auto& issue = issues[i];
            std::cout << "    {\n";
            std::cout << "      \"rule_id\": \"" << json_escape(issue.rule_id) << "\",\n";
            std::cout << "      \"title\": \"" << json_escape(issue.title) << "\",\n";
            std::cout << "      \"description\": \"" << json_escape(issue.description) << "\",\n";
            std::cout << "      \"recommendation\": \"" << json_escape(issue.recommendation) << "\",\n";
            std::cout << "      \"impact_count\": " << issue.impact_count << ",\n";
            std::cout << "      \"top_stack\": \"" << json_escape(issue.top_stack) << "\"\n";
            std::cout << "    }";
            if (i + 1 < issues.size()) std::cout << ",";
            std::cout << "\n";
        }
        std::cout << "  ]\n";
        std::cout << "}\n";

    } else if (format == OutputFormat::MARKDOWN) {
        std::cout << "# Syscall Optimization Analysis\n\n";
        std::cout << "- **Target**: `" << target_cmd << "`\n";
        std::cout << "- **Total Syscalls Executed**: `" << total_syscalls << "`\n";
        std::cout << "- **Potential Syscalls Saved**: `" << potential_savings << "`\n";
        std::cout << "- **Syscall Efficiency Score**: `" << std::fixed << std::setprecision(1) << efficiency_score << "%`\n\n";

        if (issues.empty()) {
            std::cout << "✅ **No major syscall anti-patterns detected.** Your algorithm has optimal syscall density!\n";
        } else {
            std::cout << "## Detected Anti-Patterns & Bottlenecks\n\n";
            for (const auto& issue : issues) {
                std::cout << "### ⚠️ " << issue.title << "\n";
                std::cout << "- **Rule**: `" << issue.rule_id << "`\n";
                std::cout << "- **Impact**: `" << issue.impact_count << " redundant syscalls`\n";
                std::cout << "- **Details**: " << issue.description << "\n";
                std::cout << "- **Stack Trace**: `" << issue.top_stack << "`\n";
                std::cout << "- **💡 Optimization**: " << issue.recommendation << "\n\n";
            }
        }

    } else { // REPORT format
        std::cout << "\n===============================================================\n";
        std::cout << "        SYSCALL OPTIMIZER & ANTI-PATTERN ANALYZER              \n";
        std::cout << "===============================================================\n\n";
        std::cout << "Целевой процесс:                " << target_cmd << " (PID " << g_target << ")\n";
        std::cout << "Всего системных вызовов:       " << total_syscalls << "\n";
        std::cout << "Потенциал экономии вызовов:     " << potential_savings << " сисколов\n";
        std::cout << "Индекс эффективности сисколов:  " << std::fixed << std::setprecision(1) << efficiency_score << "%\n\n";

        if (issues.empty()) {
            std::cout << "✅ Отлично! Избыточных узких мест в вызовах ядра не обнаружено.\n\n";
        } else {
            std::cout << "---------------------------------------------------------------\n";
            std::cout << "НАЙДЕННЫЕ АНТИ-ПАТТЕРНЫ И РЕКОМЕНДАЦИИ ПО ОПТИМИЗАЦИИ:\n";
            std::cout << "---------------------------------------------------------------\n\n";

            for (size_t i = 0; i < issues.size(); ++i) {
                const auto& issue = issues[i];
                std::cout << "[" << (i + 1) << "] " << issue.title << "\n";
                std::cout << "    • Правило:             " << issue.rule_id << "\n";
                std::cout << "    • Потенциал экономии: " << issue.impact_count << " сисколов\n";
                std::cout << "    • Описание:            " << issue.description << "\n";
                if (!issue.top_stack.empty()) {
                    std::cout << "    • Основной стек:       " << issue.top_stack << "\n";
                }
                std::cout << "    • 💡 КАК ОПТИМИЗИРОВАТЬ: " << issue.recommendation << "\n\n";
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Использование: sudo " << argv[0] << " [--json | --markdown | --report] <program> [args...]\n";
        std::cerr << "Пример:        sudo " << argv[0] << " --json ./demo_app\n";
        return 1;
    }

    if (geteuid() != 0) {
        std::cerr << "[!] Требуются права root (sudo).\n";
        return 1;
    }

    OutputFormat format = OutputFormat::REPORT;
    int arg_idx = 1;

    std::string first_arg = argv[1];
    if (first_arg == "--json") {
        format = OutputFormat::JSON;
        arg_idx = 2;
    } else if (first_arg == "--markdown" || first_arg == "--llm") {
        format = OutputFormat::MARKDOWN;
        arg_idx = 2;
    } else if (first_arg == "--report") {
        format = OutputFormat::REPORT;
        arg_idx = 2;
    }

    if (arg_idx >= argc) {
        std::cerr << "Использование: sudo " << argv[0] << " [--json | --markdown | --report] <program> [args...]\n";
        return 1;
    }

    std::string target_program = argv[arg_idx];

    int err = 0;
    g_dtp = dtrace_open(DTRACE_VERSION, 0, &err);
    if (!g_dtp) {
        std::cerr << "[!] dtrace_open(): " << dtrace_errmsg(nullptr, err) << "\n";
        return 1;
    }

    (void)dtrace_setopt(g_dtp, "destructive", nullptr);
    (void)dtrace_setopt(g_dtp, "quiet",       "1");
    (void)dtrace_setopt(g_dtp, "ustackframes", "12");
    (void)dtrace_setopt(g_dtp, "bufsize",      "8m");
    (void)dtrace_setopt(g_dtp, "aggsize",      "8m");
    (void)dtrace_setopt(g_dtp, "aggrate",      "10ms");
    (void)dtrace_setopt(g_dtp, "switchrate",   "10ms");

    dtrace_handle_err(g_dtp, dtrace_err_cb, nullptr);

    if (format == OutputFormat::REPORT) {
        std::cout << "[*] Запуск оптимизатора сисколов для: " << target_program << "\n";
    }

    g_target = fork();
    if (g_target < 0) {
        std::cerr << "[!] fork(): " << strerror(errno) << "\n";
        dtrace_close(g_dtp);
        return 1;
    }

    if (g_target == 0) {
        raise(SIGSTOP);
        execvp(target_program.c_str(), argv + arg_idx);
        std::cerr << "[!] execvp(): " << strerror(errno) << "\n";
        _exit(1);
    }

    int stop_status = 0;
    waitpid(g_target, &stop_status, WUNTRACED);

    char script[512];
    std::snprintf(script, sizeof(script), D_SCRIPT_TEMPLATE, (int)g_target);

    dtrace_prog_t* prog = dtrace_program_strcompile(
        g_dtp, script, DTRACE_PROBESPEC_NAME, DTRACE_C_PSPEC, 0, nullptr);

    if (!prog) {
        std::cerr << "[!] dtrace_program_strcompile(): "
                  << dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)) << "\n";
        kill(g_target, SIGKILL);
        waitpid(g_target, nullptr, 0);
        dtrace_close(g_dtp);
        return 1;
    }

    dtrace_proginfo_t info{};
    if (dtrace_program_exec(g_dtp, prog, &info) != 0 || dtrace_go(g_dtp) != 0) {
        std::cerr << "[!] Ошибка запуска DTrace трассировки.\n";
        kill(g_target, SIGKILL);
        waitpid(g_target, nullptr, 0);
        dtrace_close(g_dtp);
        return 1;
    }

    kill(g_target, SIGCONT);

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    while (!g_done.load(std::memory_order_relaxed)) {
        dtrace_sleep(g_dtp);

        int status = 0;
        pid_t w = waitpid(g_target, &status, WNOHANG);
        if (w == g_target) {
            g_done.store(true, std::memory_order_relaxed);
        }
        dtrace_aggregate_snap(g_dtp);
    }

    dtrace_stop(g_dtp);
    dtrace_aggregate_snap(g_dtp);
    dtrace_aggregate_walk(g_dtp, aggwalk_cb, nullptr);

    render_output(format, target_program);

    g_stats.clear();
    g_symbol_cache.clear();

    dtrace_close(g_dtp);

    if (kill(g_target, 0) == 0) {
        kill(g_target, SIGTERM);
        waitpid(g_target, nullptr, 0);
    }

    return 0;
}
