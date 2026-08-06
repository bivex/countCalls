/**
 * syscall_callgraph.cpp
 *
 * Высокопроизводительный генератор обратного графа системных вызовов на macOS.
 *
 * Улучшения и исправленные проблемы (Self-Audit Improvements):
 * 1. [Синхронизация процессов]: waitpid(WUNTRACED) устраняет race-condition при старте дочернего процесса
 * 2. [Агрегация символов]: Стриппинг смещений (+0x...) объединяет вызовы в одну функцию, очищая граф
 * 3. [Потокобезопасность]: std::atomic<bool> для безопасной обработки сигналов SIGINT/SIGTERM
 * 4. [Кеширование PC]: std::unordered_map для O(1) поиска резолвинга DTrace символов
 * 5. [Оптимизация дерева]: Избегаем ложных разветвлений из-за различий в инструкционных офсетах
 */

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <memory>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <cerrno>
#include <fstream>
#include <chrono>
#include <atomic>

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <dtrace.h>

enum class OutputFormat {
    TREE,       // ASCII дерево
    MARKDOWN,   // Читаемая Markdown структура для LLM
    JSON        // Структурированный JSON для LLM
};

// ─────────────────────────────────────────────────────────────────────────────
// Дерево вызовов (Оптимизировано через unordered_map)
// ─────────────────────────────────────────────────────────────────────────────

struct TreeNode {
    std::string name;
    uint64_t count = 0;
    std::unordered_map<std::string, std::shared_ptr<TreeNode>> children;

    TreeNode(std::string n = "") : name(std::move(n)) {}

    void add_path(const std::vector<std::string>& path, size_t index, uint64_t cnt) {
        count += cnt;
        if (index >= path.size()) return;

        const std::string& child_name = path[index];
        auto it = children.find(child_name);
        if (it == children.end()) {
            auto new_child = std::make_shared<TreeNode>(child_name);
            children.emplace(child_name, new_child);
            new_child->add_path(path, index + 1, cnt);
        } else {
            it->second->add_path(path, index + 1, cnt);
        }
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Глобальное состояние
// ─────────────────────────────────────────────────────────────────────────────

static dtrace_hdl_t*      g_dtp    = nullptr;
static pid_t              g_target = -1;
static std::atomic<bool>  g_done{false};

static std::unordered_map<std::string, std::shared_ptr<TreeNode>> g_syscall_trees;

// Кеш резолвинга адресов символов (uint64_t pc -> std::string symbol)
static std::unordered_map<uint64_t, std::string> g_symbol_cache;
static uint64_t g_cache_hits   = 0;
static uint64_t g_cache_misses = 0;

static const char* D_SCRIPT_TEMPLATE = R"(
syscall:::entry
/pid == %d/
{
    @[probefunc, ustack(16)] = count();
}
)";

static void sig_handler(int) {
    g_done.store(true, std::memory_order_relaxed);
}

static int dtrace_err_cb(const dtrace_errdata_t* data, void*) {
    std::cerr << "[dtrace error] " << data->dteda_msg << "\n";
    return DTRACE_HANDLE_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// Очистка имени символа: удаление смещений (+0x1a или +24) для чистой агрегации
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Поиск символа по адресу PC с кешированием и агрегацией
// ─────────────────────────────────────────────────────────────────────────────

static const std::string& resolve_pc_symbol(uint64_t pc) {
    auto it = g_symbol_cache.find(pc);
    if (it != g_symbol_cache.end()) {
        g_cache_hits++;
        return it->second;
    }

    g_cache_misses++;
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

// ─────────────────────────────────────────────────────────────────────────────
// Callback обхода DTrace агрегации
// ─────────────────────────────────────────────────────────────────────────────

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

    std::vector<std::string> frames;
    frames.reserve(num_frames);

    for (uint32_t i = 0; i < num_frames; ++i) {
        uint64_t pc = pc_addrs[i];
        if (pc == 0) break;
        
        const std::string& sym = resolve_pc_symbol(pc);
        // Фильтруем дублирование подряд идущих одинаковых символов
        if (frames.empty() || frames.back() != sym) {
            frames.push_back(sym);
        }
    }

    if (syscall_name && syscall_name[0] != '\0') {
        std::string sys_str = syscall_name;
        auto& root = g_syscall_trees[sys_str];
        if (!root) {
            root = std::make_shared<TreeNode>(sys_str);
        }
        if (!frames.empty()) {
            root->add_path(frames, 0, count);
        }
    }

    return DTRACE_AGGWALK_NEXT;
}

// ─────────────────────────────────────────────────────────────────────────────
// Экранирование JSON
// ─────────────────────────────────────────────────────────────────────────────

static std::string json_escape(const std::string& s) {
    std::string res;
    res.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  res += "\\\""; break;
            case '\\': res += "\\\\"; break;
            case '\b': res += "\\b";  break;
            case '\f': res += "\\f";  break;
            case '\n': res += "\\n";  break;
            case '\r': res += "\\r";  break;
            case '\t': res += "\\t";  break;
            default:   res += c;      break;
        }
    }
    return res;
}

// ─────────────────────────────────────────────────────────────────────────────
// ASCII Tree
// ─────────────────────────────────────────────────────────────────────────────

static void print_ascii_tree(const std::shared_ptr<TreeNode>& node, const std::string& prefix, bool is_last) {
    if (!node) return;

    std::cout << prefix;
    std::cout << (is_last ? "└── " : "├── ");
    std::cout << node->name << " [" << node->count << " calls]\n";

    std::string child_prefix = prefix + (is_last ? "    " : "│   ");

    std::vector<std::shared_ptr<TreeNode>> children_list;
    children_list.reserve(node->children.size());
    for (auto& [_, child] : node->children) children_list.push_back(child);
    std::sort(children_list.begin(), children_list.end(), [](const auto& a, const auto& b) {
        return a->count > b->count;
    });

    for (size_t i = 0; i < children_list.size(); ++i) {
        print_ascii_tree(children_list[i], child_prefix, i == children_list.size() - 1);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Clean Markdown
// ─────────────────────────────────────────────────────────────────────────────

static void print_markdown_tree(const std::shared_ptr<TreeNode>& node, int depth) {
    if (!node) return;

    std::string indent(depth * 2, ' ');
    std::cout << indent << "- `" << node->name << "` (" << node->count << " calls)\n";

    std::vector<std::shared_ptr<TreeNode>> children_list;
    children_list.reserve(node->children.size());
    for (auto& [_, child] : node->children) children_list.push_back(child);
    std::sort(children_list.begin(), children_list.end(), [](const auto& a, const auto& b) {
        return a->count > b->count;
    });

    for (const auto& child : children_list) {
        print_markdown_tree(child, depth + 1);
    }
}

static void print_markdown_format(const std::string& target_cmd) {
    std::cout << "# Reverse Call Graph\n\n";
    std::cout << "- **Target**: `" << target_cmd << "`\n";
    std::cout << "- **PID**: `" << g_target << "`\n";
    std::cout << "- **Total Unique Syscalls**: `" << g_syscall_trees.size() << "`\n";
    std::cout << "- **Symbol Cache**: `" << g_cache_hits << " hits / " << g_cache_misses << " misses` ("
              << (g_cache_hits + g_cache_misses > 0 ? (100.0 * g_cache_hits / (g_cache_hits + g_cache_misses)) : 0.0)
              << "% hit rate)\n\n";

    std::vector<std::pair<std::string, std::shared_ptr<TreeNode>>> sorted_trees(
        g_syscall_trees.begin(), g_syscall_trees.end());

    std::sort(sorted_trees.begin(), sorted_trees.end(), [](const auto& a, const auto& b) {
        return a.second->count > b.second->count;
    });

    for (auto& [sys_name, tree] : sorted_trees) {
        std::cout << "## Syscall: `" << sys_name << "` (Total calls: " << tree->count << ")\n\n";

        std::vector<std::shared_ptr<TreeNode>> children_list;
        children_list.reserve(tree->children.size());
        for (auto& [_, child] : tree->children) children_list.push_back(child);
        std::sort(children_list.begin(), children_list.end(), [](const auto& a, const auto& b) {
            return a->count > b->count;
        });

        for (const auto& child : children_list) {
            print_markdown_tree(child, 0);
        }
        std::cout << "\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Structured JSON
// ─────────────────────────────────────────────────────────────────────────────

static void print_json_node(const std::shared_ptr<TreeNode>& node, int indent_level) {
    std::string indent(indent_level * 2, ' ');
    std::cout << indent << "{\n";
    std::cout << indent << "  \"name\": \"" << json_escape(node->name) << "\",\n";
    std::cout << indent << "  \"count\": " << node->count;

    if (!node->children.empty()) {
        std::cout << ",\n" << indent << "  \"children\": [\n";
        
        std::vector<std::shared_ptr<TreeNode>> children_list;
        children_list.reserve(node->children.size());
        for (auto& [_, child] : node->children) children_list.push_back(child);
        std::sort(children_list.begin(), children_list.end(), [](const auto& a, const auto& b) {
            return a->count > b->count;
        });

        for (size_t i = 0; i < children_list.size(); ++i) {
            print_json_node(children_list[i], indent_level + 2);
            if (i + 1 < children_list.size()) std::cout << ",";
            std::cout << "\n";
        }
        std::cout << indent << "  ]\n";
    } else {
        std::cout << "\n";
    }
    std::cout << indent << "}";
}

static void print_json_format(const std::string& target_cmd) {
    std::cout << "{\n";
    std::cout << "  \"target\": \"" << json_escape(target_cmd) << "\",\n";
    std::cout << "  \"pid\": " << g_target << ",\n";
    std::cout << "  \"unique_syscalls\": " << g_syscall_trees.size() << ",\n";
    std::cout << "  \"symbol_cache\": {\n";
    std::cout << "    \"hits\": " << g_cache_hits << ",\n";
    std::cout << "    \"misses\": " << g_cache_misses << "\n";
    std::cout << "  },\n";
    std::cout << "  \"syscalls\": [\n";

    std::vector<std::pair<std::string, std::shared_ptr<TreeNode>>> sorted_trees(
        g_syscall_trees.begin(), g_syscall_trees.end());

    std::sort(sorted_trees.begin(), sorted_trees.end(), [](const auto& a, const auto& b) {
        return a.second->count > b.second->count;
    });

    for (size_t i = 0; i < sorted_trees.size(); ++i) {
        auto& [sys_name, tree] = sorted_trees[i];
        std::cout << "    {\n";
        std::cout << "      \"syscall\": \"" << json_escape(sys_name) << "\",\n";
        std::cout << "      \"total_calls\": " << tree->count << ",\n";
        std::cout << "      \"tree\": [\n";

        std::vector<std::shared_ptr<TreeNode>> children_list;
        children_list.reserve(tree->children.size());
        for (auto& [_, child] : tree->children) children_list.push_back(child);
        std::sort(children_list.begin(), children_list.end(), [](const auto& a, const auto& b) {
            return a->count > b->count;
        });

        for (size_t j = 0; j < children_list.size(); ++j) {
            print_json_node(children_list[j], 4);
            if (j + 1 < children_list.size()) std::cout << ",";
            std::cout << "\n";
        }
        std::cout << "      ]\n";

        std::cout << "    }";
        if (i + 1 < sorted_trees.size()) std::cout << ",";
        std::cout << "\n";
    }

    std::cout << "  ]\n";
    std::cout << "}\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Вывод результатов
// ─────────────────────────────────────────────────────────────────────────────

static void render_output(OutputFormat format, const std::string& target_cmd) {
    if (g_syscall_trees.empty()) {
        if (format == OutputFormat::JSON) {
            std::cout << "{\"target\": \"" << json_escape(target_cmd) << "\", \"syscalls\": []}\n";
        } else if (format == OutputFormat::MARKDOWN) {
            std::cout << "# Reverse Call Graph\nNo syscall trace data collected.\n";
        } else {
            std::cout << "\n[!] Данные стека вызовов отсутствуют.\n";
        }
        return;
    }

    switch (format) {
        case OutputFormat::JSON:
            print_json_format(target_cmd);
            break;
        case OutputFormat::MARKDOWN:
            print_markdown_format(target_cmd);
            break;
        case OutputFormat::TREE:
        default: {
            std::cout << "\n===============================================================\n";
            std::cout << "       ОБРАТНЫЙ ГРАФ / ДЕРЕВО ВЫЗОВОВ (REVERSE CALL GRAPH)      \n";
            std::cout << "       [ Syscall -> Calling Stack Frames -> Main / Caller ]     \n";
            std::cout << "===============================================================\n\n";

            std::vector<std::pair<std::string, std::shared_ptr<TreeNode>>> sorted_trees(
                g_syscall_trees.begin(), g_syscall_trees.end());

            std::sort(sorted_trees.begin(), sorted_trees.end(), [](const auto& a, const auto& b) {
                return a.second->count > b.second->count;
            });

            for (auto& [sys_name, tree] : sorted_trees) {
                std::cout << "SYSCALL: " << sys_name << " (всего: " << tree->count << " вызовов)\n";
                std::vector<std::shared_ptr<TreeNode>> children_list;
                children_list.reserve(tree->children.size());
                for (auto& [_, child] : tree->children) children_list.push_back(child);
                std::sort(children_list.begin(), children_list.end(), [](const auto& a, const auto& b) {
                    return a->count > b->count;
                });

                for (size_t i = 0; i < children_list.size(); ++i) {
                    print_ascii_tree(children_list[i], "", i == children_list.size() - 1);
                }
                std::cout << "\n";
            }
            break;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Использование: sudo " << argv[0] << " [--json | --markdown | --tree] <program> [args...]\n";
        std::cerr << "Пример:        sudo " << argv[0] << " --json /bin/ls -la /tmp\n";
        return 1;
    }

    if (geteuid() != 0) {
        std::cerr << "[!] Требуются права root (sudo).\n";
        return 1;
    }

    OutputFormat format = OutputFormat::TREE;
    int arg_idx = 1;

    std::string first_arg = argv[1];
    if (first_arg == "--json") {
        format = OutputFormat::JSON;
        arg_idx = 2;
    } else if (first_arg == "--markdown" || first_arg == "--llm") {
        format = OutputFormat::MARKDOWN;
        arg_idx = 2;
    } else if (first_arg == "--tree") {
        format = OutputFormat::TREE;
        arg_idx = 2;
    }

    if (arg_idx >= argc) {
        std::cerr << "Использование: sudo " << argv[0] << " [--json | --markdown | --tree] <program> [args...]\n";
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
    (void)dtrace_setopt(g_dtp, "ustackframes", "16");
    (void)dtrace_setopt(g_dtp, "bufsize",      "8m");
    (void)dtrace_setopt(g_dtp, "aggsize",      "8m");
    (void)dtrace_setopt(g_dtp, "switchrate",   "10hz");

    dtrace_handle_err(g_dtp, dtrace_err_cb, nullptr);

    if (format == OutputFormat::TREE) {
        std::cout << "[*] Запускаем дочерний процесс: " << target_program << "\n";
    }

    auto start_time = std::chrono::high_resolution_clock::now();

    g_target = fork();
    if (g_target < 0) {
        std::cerr << "[!] fork(): " << strerror(errno) << "\n";
        dtrace_close(g_dtp);
        return 1;
    }

    if (g_target == 0) {
        // Подготовка к остановке дочернего процесса
        raise(SIGSTOP);
        execvp(target_program.c_str(), argv + arg_idx);
        std::cerr << "[!] execvp(): " << strerror(errno) << "\n";
        _exit(1);
    }

    // FIX: Надёжная синхронизация процессов: ждём момента, когда дочерний процесс остановится на SIGSTOP
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

    // Возобновляем дочерний процесс ПОСЛЕ компиляции и старта DTrace
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

    auto walk_start = std::chrono::high_resolution_clock::now();
    dtrace_aggregate_walk(g_dtp, aggwalk_cb, nullptr);
    auto walk_end = std::chrono::high_resolution_clock::now();

    render_output(format, target_program);

    if (format == OutputFormat::TREE) {
        auto total_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(walk_end - start_time).count();
        auto walk_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(walk_end - walk_start).count();
        std::cout << "[*] Профилирование и метрики:\n";
        std::cout << "    - Общее время: " << total_elapsed << " мс\n";
        std::cout << "    - Сбор стеков: " << walk_elapsed << " мкс\n";
        std::cout << "    - Кеш символов: " << g_cache_hits << " hits / " << g_cache_misses << " misses\n";
    }

    // Освобождаем память дерева и кеша символов до dtrace_close
    g_syscall_trees.clear();
    g_symbol_cache.clear();

    dtrace_close(g_dtp);

    if (kill(g_target, 0) == 0) {
        kill(g_target, SIGTERM);
        waitpid(g_target, nullptr, 0);
    }

    return 0;
}
