/**
 * syscall_counter.cpp
 *
 * Подсчёт системных вызовов дочернего процесса на macOS с использованием DTrace API.
 *
 * Сборка:
 *   clang++ -std=c++17 -O2 -o syscall_counter syscall_counter.cpp -ldtrace
 *
 * Запуск (нужен root):
 *   sudo ./syscall_counter <program> [args...]
 *
 * Пример:
 *   sudo ./syscall_counter /bin/ls -la /tmp
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

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <dtrace.h>

// ─────────────────────────────────────────────────────────────────────────────
// Глобальные переменные
// ─────────────────────────────────────────────────────────────────────────────

static dtrace_hdl_t* g_dtp    = nullptr;   // дескриптор DTrace
static pid_t         g_target = -1;        // PID дочернего процесса
static volatile bool g_done   = false;     // флаг завершения

// Результаты: имя_syscall → количество
static std::map<std::string, uint64_t> g_counts;

// ─────────────────────────────────────────────────────────────────────────────
// D-скрипт: считаем вхождения каждого syscall для конкретного PID
// ─────────────────────────────────────────────────────────────────────────────

static const char* D_SCRIPT_TEMPLATE = R"(
syscall:::entry
/pid == %d/
{
    @counts[probefunc] = count();
}
)";

// ─────────────────────────────────────────────────────────────────────────────
// Обработка сигналов
// ─────────────────────────────────────────────────────────────────────────────

static void sig_handler(int /*sig*/) {
    g_done = true;
    if (g_dtp) {
        dtrace_stop(g_dtp);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Callback: обходим агрегацию @counts из D-скрипта
// ─────────────────────────────────────────────────────────────────────────────

static int aggwalk_cb(const dtrace_aggdata_t* data, void* /*uarg*/) {
    // Ключ агрегации — строка (имя пробы / probefunc)
    const dtrace_aggdesc_t* agg = data->dtada_desc;

    // Получаем имя syscall из первого аргумента агрегации
    const dtrace_recdesc_t* rec = &agg->dtagd_rec[1]; // [0] — epid, [1] — ключ

    const char* name = data->dtada_data + rec->dtrd_offset;

    // Значение агрегации count() — последняя запись
    const dtrace_recdesc_t* val_rec = &agg->dtagd_rec[agg->dtagd_nrecs - 1];
    uint64_t count = 0;
    std::memcpy(&count, data->dtada_data + val_rec->dtrd_offset, sizeof(uint64_t));

    if (name && name[0] != '\0') {
        g_counts[name] += count;
    }

    return DTRACE_AGGWALK_NEXT;
}

// ─────────────────────────────────────────────────────────────────────────────
// Callback: вывод ошибок DTrace в stderr
// ─────────────────────────────────────────────────────────────────────────────

static int dtrace_err_cb(const dtrace_errdata_t* data, void* /*uarg*/) {
    std::cerr << "[dtrace error] " << data->dteda_msg << "\n";
    return DTRACE_HANDLE_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// Вывод результатов
// ─────────────────────────────────────────────────────────────────────────────

static void print_results() {
    if (g_counts.empty()) {
        std::cout << "\nНет данных о syscall'ах.\n";
        return;
    }

    // Сортируем по убыванию количества
    std::vector<std::pair<std::string, uint64_t>> sorted(g_counts.begin(), g_counts.end());
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    uint64_t total = 0;
    for (auto& [name, cnt] : sorted) total += cnt;

    const int W_NAME  = 28;
    const int W_COUNT = 10;
    const int W_PCT   = 8;

    std::string sep(W_NAME + W_COUNT + W_PCT + 4, '-');

    std::cout << "\n";
    std::cout << "+" << sep << "+\n";
    std::cout << "|"
              << std::left  << std::setw(W_NAME)  << "  Syscall"
              << std::right << std::setw(W_COUNT)  << "Calls"
              << std::right << std::setw(W_PCT)    << "  %   "
              << " |\n";
    std::cout << "+" << sep << "+\n";

    for (auto& [name, cnt] : sorted) {
        double pct = 100.0 * cnt / total;
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

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Использование: sudo " << argv[0] << " <program> [args...]\n";
        std::cerr << "Пример:        sudo " << argv[0] << " /bin/ls -la /tmp\n";
        return 1;
    }

    if (geteuid() != 0) {
        std::cerr << "[!] Требуются права root (sudo).\n";
        return 1;
    }

    // ── 1. Инициализируем DTrace ─────────────────────────────────────────────
    int err = 0;
    g_dtp = dtrace_open(DTRACE_VERSION, 0, &err);
    if (!g_dtp) {
        std::cerr << "[!] dtrace_open(): " << dtrace_errmsg(nullptr, err) << "\n";
        return 1;
    }

    // Включаем деструктивные действия (нужно для grabbing процессов)
    (void)dtrace_setopt(g_dtp, "destructive", nullptr);
    (void)dtrace_setopt(g_dtp, "quiet",       "1");

    dtrace_handle_err(g_dtp, dtrace_err_cb, nullptr);

    // ── 2. Запускаем дочерний процесс ────────────────────────────────────────
    std::cout << "[*] Запускаем: " << argv[1] << "\n";

    g_target = fork();
    if (g_target < 0) {
        std::cerr << "[!] fork(): " << strerror(errno) << "\n";
        dtrace_close(g_dtp);
        return 1;
    }

    if (g_target == 0) {
        // Дочерний процесс: немного ждём, чтобы DTrace успел подключиться
        // (альтернатива — grab после fork с SIGSTOP/SIGCONT)
        raise(SIGSTOP);
        execvp(argv[1], argv + 1);
        std::cerr << "[!] execvp(): " << strerror(errno) << "\n";
        _exit(1);
    }

    // ── 3. Компилируем D-скрипт ──────────────────────────────────────────────
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
    if (dtrace_program_exec(g_dtp, prog, &info) != 0) {
        std::cerr << "[!] dtrace_program_exec(): "
                  << dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)) << "\n";
        kill(g_target, SIGKILL);
        waitpid(g_target, nullptr, 0);
        dtrace_close(g_dtp);
        return 1;
    }

    if (dtrace_go(g_dtp) != 0) {
        std::cerr << "[!] dtrace_go(): "
                  << dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)) << "\n";
        kill(g_target, SIGKILL);
        waitpid(g_target, nullptr, 0);
        dtrace_close(g_dtp);
        return 1;
    }

    // ── 4. Возобновляем дочерний процесс ─────────────────────────────────────
    kill(g_target, SIGCONT);

    // ── 5. Обрабатываем сигналы завершения ───────────────────────────────────
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    // ── 6. Основной цикл: ждём завершения дочернего процесса ─────────────────
    std::cout << "[*] Трассировка PID " << g_target
              << "… (Ctrl+C для досрочной остановки)\n\n";

    while (!g_done) {
        // Обрабатываем буферы DTrace
        dtrace_sleep(g_dtp);

        int status = 0;
        pid_t w = waitpid(g_target, &status, WNOHANG);
        if (w == g_target) {
            g_done = true;
            if (WIFEXITED(status)) {
                std::cout << "\n[*] Процесс завершился с кодом " << WEXITSTATUS(status) << "\n";
            } else if (WIFSIGNALED(status)) {
                std::cout << "\n[*] Процесс убит сигналом " << WTERMSIG(status) << "\n";
            }
        }

        // Собираем агрегацию
        dtrace_aggregate_snap(g_dtp);
    }

    // ── 7. Собираем финальную агрегацию ──────────────────────────────────────
    dtrace_stop(g_dtp);
    dtrace_aggregate_snap(g_dtp);
    dtrace_aggregate_walk(g_dtp, aggwalk_cb, nullptr);

    // ── 8. Вывод результатов ─────────────────────────────────────────────────
    print_results();

    // ── 9. Очистка ───────────────────────────────────────────────────────────
    dtrace_close(g_dtp);

    // Если дочерний процесс всё ещё жив (Ctrl+C), убиваем его
    if (kill(g_target, 0) == 0) {
        kill(g_target, SIGTERM);
        waitpid(g_target, nullptr, 0);
    }

    return 0;
}
