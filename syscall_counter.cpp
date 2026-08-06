/**
 * syscall_counter.cpp
 *
 * Подсчёт системных вызовов дочернего процесса на macOS с поддержкой вывода для LLM.
 *
 * Сборка:
 *   clang++ -std=c++17 -O2 -o syscall_counter syscall_counter.cpp -ldtrace
 *
 * Запуск (нужен root):
 *   sudo ./syscall_counter [--json | --markdown | --table] <program> [args...]
 */

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <cerrno>
#include <atomic>

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <dtrace.h>

enum class OutputFormat {
    TABLE,      // Таблица для консоли
    MARKDOWN,   // Markdown список для LLM
    JSON        // JSON объект для LLM
};

static dtrace_hdl_t*     g_dtp    = nullptr;
static pid_t             g_target = -1;
static std::atomic<bool> g_done{false};

static std::map<std::string, uint64_t> g_counts;

static const char* D_SCRIPT_TEMPLATE = R"(
syscall:::entry
/pid == %d/
{
    @counts[probefunc] = count();
}
)";

static void sig_handler(int) {
    g_done.store(true, std::memory_order_relaxed);
}

static int aggwalk_cb(const dtrace_aggdata_t* data, void*) {
    const dtrace_aggdesc_t* agg = data->dtada_desc;
    const dtrace_recdesc_t* rec = &agg->dtagd_rec[1];
    const char* name = data->dtada_data + rec->dtrd_offset;

    const dtrace_recdesc_t* val_rec = &agg->dtagd_rec[agg->dtagd_nrecs - 1];
    uint64_t count = 0;
    std::memcpy(&count, data->dtada_data + val_rec->dtrd_offset, sizeof(uint64_t));

    if (name && name[0] != '\0') {
        g_counts[name] += count;
    }
    return DTRACE_AGGWALK_NEXT;
}

static int dtrace_err_cb(const dtrace_errdata_t* data, void*) {
    std::cerr << "[dtrace error] " << data->dteda_msg << "\n";
    return DTRACE_HANDLE_OK;
}

static std::string json_escape(const std::string& s) {
    std::ostringstream ss;
    for (char c : s) {
        if (c == '"') ss << "\\\"";
        else if (c == '\\') ss << "\\\\";
        else ss << c;
    }
    return ss.str();
}

static void render_output(OutputFormat format, const std::string& target_cmd) {
    std::vector<std::pair<std::string, uint64_t>> sorted(g_counts.begin(), g_counts.end());
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });

    uint64_t total = 0;
    for (auto& [name, cnt] : sorted) total += cnt;

    if (format == OutputFormat::JSON) {
        std::cout << "{\n";
        std::cout << "  \"target\": \"" << json_escape(target_cmd) << "\",\n";
        std::cout << "  \"pid\": " << g_target << ",\n";
        std::cout << "  \"total_calls\": " << total << ",\n";
        std::cout << "  \"unique_syscalls\": " << sorted.size() << ",\n";
        std::cout << "  \"syscalls\": [\n";
        for (size_t i = 0; i < sorted.size(); ++i) {
            double pct = total > 0 ? (100.0 * sorted[i].second / total) : 0.0;
            std::cout << "    {\"syscall\": \"" << json_escape(sorted[i].first)
                      << "\", \"count\": " << sorted[i].second
                      << ", \"percentage\": " << std::fixed << std::setprecision(2) << pct << "}";
            if (i + 1 < sorted.size()) std::cout << ",";
            std::cout << "\n";
        }
        std::cout << "  ]\n";
        std::cout << "}\n";
    } else if (format == OutputFormat::MARKDOWN) {
        std::cout << "# Syscall Summary\n\n";
        std::cout << "- **Target**: `" << target_cmd << "`\n";
        std::cout << "- **Total Calls**: `" << total << "`\n";
        std::cout << "- **Unique Syscalls**: `" << sorted.size() << "`\n\n";
        std::cout << "| Syscall | Calls | Percentage |\n";
        std::cout << "|---|---|---|\n";
        for (auto& [name, cnt] : sorted) {
            double pct = total > 0 ? (100.0 * cnt / total) : 0.0;
            std::cout << "| `" << name << "` | " << cnt << " | "
                      << std::fixed << std::setprecision(1) << pct << "% |\n";
        }
    } else {
        if (sorted.empty()) {
            std::cout << "\nНет данных о syscall'ах.\n";
            return;
        }

        const int W_NAME  = 28;
        const int W_COUNT = 10;
        const int W_PCT   = 8;
        std::string sep(W_NAME + W_COUNT + W_PCT + 4, '-');

        std::cout << "\n+" << sep << "+\n";
        std::cout << "|"
                  << std::left  << std::setw(W_NAME)  << "  Syscall"
                  << std::right << std::setw(W_COUNT)  << "Calls"
                  << std::right << std::setw(W_PCT)    << "  %   "
                  << " |\n";
        std::cout << "+" << sep << "+\n";

        for (auto& [name, cnt] : sorted) {
            double pct = total > 0 ? (100.0 * cnt / total) : 0.0;
            std::cout << "| "
                      << std::left  << std::setw(W_NAME - 1) << name
                      << std::right << std::setw(W_COUNT)     << cnt
                      << std::right << std::setw(W_PCT - 1)   << std::fixed << std::setprecision(1) << pct << "%"
                      << " |\n";
        }

        std::cout << "+" << sep << "+\n";
        std::cout << "| "
                  << std::left  << std::setw(W_NAME - 1) << "TOTAL"
                  << std::right << std::setw(W_COUNT)     << total
                  << std::right << std::setw(W_PCT - 1)   << 100.0 << "%"
                  << " |\n";
        std::cout << "+" << sep << "+\n";
        std::cout << "\nПодсчитано уникальных syscall'ов: " << sorted.size() << "\n\n";
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Использование: sudo " << argv[0] << " [--json | --markdown | --table] <program> [args...]\n";
        std::cerr << "Пример:        sudo " << argv[0] << " --json /bin/ls -la /tmp\n";
        return 1;
    }

    if (geteuid() != 0) {
        std::cerr << "[!] Требуются права root (sudo).\n";
        return 1;
    }

    OutputFormat format = OutputFormat::TABLE;
    int arg_idx = 1;

    std::string first_arg = argv[1];
    if (first_arg == "--json") {
        format = OutputFormat::JSON;
        arg_idx = 2;
    } else if (first_arg == "--markdown" || first_arg == "--llm") {
        format = OutputFormat::MARKDOWN;
        arg_idx = 2;
    } else if (first_arg == "--table") {
        format = OutputFormat::TABLE;
        arg_idx = 2;
    }

    if (arg_idx >= argc) {
        std::cerr << "Использование: sudo " << argv[0] << " [--json | --markdown | --table] <program> [args...]\n";
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
    (void)dtrace_setopt(g_dtp, "aggrate",     "10ms");
    (void)dtrace_setopt(g_dtp, "switchrate",  "10ms");

    dtrace_handle_err(g_dtp, dtrace_err_cb, nullptr);

    if (format == OutputFormat::TABLE) {
        std::cout << "[*] Запускаем: " << target_program << "\n";
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

    // Синхронизация дочернего процесса
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
        std::cerr << "[!] dtrace error\n";
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

    dtrace_close(g_dtp);

    if (kill(g_target, 0) == 0) {
        kill(g_target, SIGTERM);
        waitpid(g_target, nullptr, 0);
    }

    return 0;
}
