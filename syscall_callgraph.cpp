/**
 * syscall_callgraph.cpp
 *
 * Построение обратного графа/дерева вызовов (Reverse Call Graph/Tree)
 * для системных вызовов процесса на macOS с поддержкой форматирования для LLM.
 *
 * Сборка:
 *   clang++ -std=c++17 -O2 -o syscall_callgraph syscall_callgraph.cpp -ldtrace
 *
 * Запуск (нужен root):
 *   sudo ./syscall_callgraph [--json | --markdown | --tree] <program> [args...]
 */

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <cerrno>
#include <fstream>

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <dtrace.h>

enum class OutputFormat {
    TREE,       // ASCII дерево
    MARKDOWN,   // Читкая Markdown структура для LLM
    JSON        // Структурированный JSON для LLM
};

// ─────────────────────────────────────────────────────────────────────────────
// Дерево вызовов (Call Tree Node)
// ─────────────────────────────────────────────────────────────────────────────

struct TreeNode {
    std::string name;
    uint64_t count = 0;
    std::map<std::string, std::shared_ptr<TreeNode>> children;

    TreeNode(std::string n = "") : name(std::move(n)) {}

    void add_path(const std::vector<std::string>& path, size_t index, uint64_t cnt) {
        count += cnt;
        if (index >= path.size()) return;

        const std::string& child_name = path[index];
        auto& child = children[child_name];
        if (!child) {
            child = std::make_shared<TreeNode>(child_name);
        }
        child->add_path(path, index + 1, cnt);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Глобальное состояние
// ─────────────────────────────────────────────────────────────────────────────

static dtrace_hdl_t* g_dtp    = nullptr;
static pid_t         g_target = -1;
static volatile bool g_done   = false;

static std::map<std::string, std::shared_ptr<TreeNode>> g_syscall_trees;

static const char* D_SCRIPT_TEMPLATE = R"(
syscall:::entry
/pid == %d/
{
    @[probefunc, ustack(16)] = count();
}
)";

static void sig_handler(int) {
    g_done = true;
    if (g_dtp) dtrace_stop(g_dtp);
}

static int dtrace_err_cb(const dtrace_errdata_t* data, void*) {
    std::cerr << "[dtrace error] " << data->dteda_msg << "\n";
    return DTRACE_HANDLE_OK;
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
    char symbuf[1024];

    for (uint32_t i = 0; i < num_frames; ++i) {
        uint64_t pc = pc_addrs[i];
        if (pc == 0) break;

        if (dtrace_addr2str(g_dtp, pc, symbuf, sizeof(symbuf)) == 0) {
            frames.push_back(symbuf);
        } else {
            std::stringstream ss;
            ss << "0x" << std::hex << pc;
            frames.push_back(ss.str());
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
// Вспомогательные функции экранирования JSON
// ─────────────────────────────────────────────────────────────────────────────

static std::string json_escape(const std::string& s) {
    std::ostringstream ss;
    for (char c : s) {
        switch (c) {
            case '"':  ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\b': ss << "\\b";  break;
            case '\f': ss << "\\f";  break;
            case '\n': ss << "\\n";  break;
            case '\r': ss << "\\r";  break;
            case '\t': ss << "\\t";  break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                } else {
                    ss << c;
                }
        }
    }
    return ss.str();
}

// ─────────────────────────────────────────────────────────────────────────────
// Форматирование 1: ASCII Tree (Для человека)
// ─────────────────────────────────────────────────────────────────────────────

static void print_ascii_tree(const std::shared_ptr<TreeNode>& node, const std::string& prefix, bool is_last) {
    if (!node) return;

    std::cout << prefix;
    std::cout << (is_last ? "└── " : "├── ");
    std::cout << node->name << " [" << node->count << " calls]\n";

    std::string child_prefix = prefix + (is_last ? "    " : "│   ");

    std::vector<std::shared_ptr<TreeNode>> children_list;
    for (auto& [_, child] : node->children) children_list.push_back(child);
    std::sort(children_list.begin(), children_list.end(), [](const auto& a, const auto& b) {
        return a->count > b->count;
    });

    for (size_t i = 0; i < children_list.size(); ++i) {
        print_ascii_tree(children_list[i], child_prefix, i == children_list.size() - 1);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Форматирование 2: Clean Markdown (Удобно для LLM)
// ─────────────────────────────────────────────────────────────────────────────

static void print_markdown_tree(const std::shared_ptr<TreeNode>& node, int depth) {
    if (!node) return;

    std::string indent(depth * 2, ' ');
    std::cout << indent << "- `" << node->name << "` (" << node->count << " calls)\n";

    std::vector<std::shared_ptr<TreeNode>> children_list;
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
    std::cout << "- **Total Unique Syscalls**: `" << g_syscall_trees.size() << "`\n\n";

    std::vector<std::pair<std::string, std::shared_ptr<TreeNode>>> sorted_trees(
        g_syscall_trees.begin(), g_syscall_trees.end());

    std::sort(sorted_trees.begin(), sorted_trees.end(), [](const auto& a, const auto& b) {
        return a.second->count > b.second->count;
    });

    for (auto& [sys_name, tree] : sorted_trees) {
        std::cout << "## Syscall: `" << sys_name << "` (Total calls: " << tree->count << ")\n\n";

        std::vector<std::shared_ptr<TreeNode>> children_list;
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
// Форматирование 3: Structured JSON (Удобно для LLM / API)
// ─────────────────────────────────────────────────────────────────────────────

static void print_json_node(const std::shared_ptr<TreeNode>& node, int indent_level) {
    std::string indent(indent_level * 2, ' ');
    std::cout << indent << "{\n";
    std::cout << indent << "  \"name\": \"" << json_escape(node->name) << "\",\n";
    std::cout << indent << "  \"count\": " << node->count;

    if (!node->children.empty()) {
        std::cout << ",\n" << indent << "  \"children\": [\n";
        
        std::vector<std::shared_ptr<TreeNode>> children_list;
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
        std::cout << "      \"tree\": ";

        // Экспортируем вектор поддеревьев
        std::cout << "[\n";
        std::vector<std::shared_ptr<TreeNode>> children_list;
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

    dtrace_handle_err(g_dtp, dtrace_err_cb, nullptr);

    if (format == OutputFormat::TREE) {
        std::cout << "[*] Запускаем дочерний процесс: " << target_program << "\n";
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

    if (format == OutputFormat::TREE) {
        std::cout << "[*] Сбор стеков вызовов для PID " << g_target << "...\n";
    }

    while (!g_done) {
        dtrace_sleep(g_dtp);

        int status = 0;
        pid_t w = waitpid(g_target, &status, WNOHANG);
        if (w == g_target) {
            g_done = true;
        }
        dtrace_aggregate_snap(g_dtp);
    }

    dtrace_stop(g_dtp);
    dtrace_aggregate_snap(g_dtp);
    dtrace_aggregate_walk(g_dtp, aggwalk_cb, nullptr);

    // Выводим выбранный формат
    render_output(format, target_program);

    dtrace_close(g_dtp);

    if (kill(g_target, 0) == 0) {
        kill(g_target, SIGTERM);
        waitpid(g_target, nullptr, 0);
    }

    return 0;
}
