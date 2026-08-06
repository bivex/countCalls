/**
 * syscall_callgraph.cpp
 *
 * Построение обратного графа/дерева вызовов (Reverse Call Graph/Tree)
 * для системных вызовов процесса на macOS с использованием DTrace ustack() и dtrace_addr2str().
 *
 * Сборка:
 *   clang++ -std=c++17 -O2 -o syscall_callgraph syscall_callgraph.cpp -ldtrace
 *
 * Запуск (нужен root):
 *   sudo ./syscall_callgraph <program> [args...]
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

// Корневое дерево вызовов: Syscall -> Frame 1 -> Frame 2 -> ... -> Caller/Main
static std::map<std::string, std::shared_ptr<TreeNode>> g_syscall_trees;

// D-скрипт с ustack()
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
// Callback обхода DTrace агрегации для ustack
// ─────────────────────────────────────────────────────────────────────────────

static int aggwalk_cb(const dtrace_aggdata_t* data, void*) {
    const dtrace_aggdesc_t* agg = data->dtada_desc;

    // rec[0]: epid
    // rec[1]: probefunc (имя syscall)
    // rec[2]: ustack record
    // last rec: count()

    if (agg->dtagd_nrecs < 3) return DTRACE_AGGWALK_NEXT;

    const dtrace_recdesc_t* rec_syscall = &agg->dtagd_rec[1];
    const char* syscall_name = data->dtada_data + rec_syscall->dtrd_offset;

    // Считываем count
    const dtrace_recdesc_t* val_rec = &agg->dtagd_rec[agg->dtagd_nrecs - 1];
    uint64_t count = 0;
    std::memcpy(&count, data->dtada_data + val_rec->dtrd_offset, sizeof(uint64_t));

    // Считываем ustack адреса
    const dtrace_recdesc_t* rec_stack = &agg->dtagd_rec[2];
    caddr_t stack_buf = data->dtada_data + rec_stack->dtrd_offset;
    uint32_t num_frames = rec_stack->dtrd_size / sizeof(uint64_t);
    const uint64_t* pc_addrs = reinterpret_cast<const uint64_t*>(stack_buf);

    std::vector<std::string> frames;
    char symbuf[1024];

    for (uint32_t i = 0; i < num_frames; ++i) {
        uint64_t pc = pc_addrs[i];
        if (pc == 0) break; // конец стека вызовов

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
// Вывод обратного дерева вызовов (ASCII Tree)
// ─────────────────────────────────────────────────────────────────────────────

static void print_ascii_tree(const std::shared_ptr<TreeNode>& node, const std::string& prefix, bool is_last) {
    if (!node) return;

    std::cout << prefix;
    std::cout << (is_last ? "└── " : "├── ");
    std::cout << node->name << " [" << node->count << " calls]\n";

    std::string child_prefix = prefix + (is_last ? "    " : "│   ");

    std::vector<std::shared_ptr<TreeNode>> children_list;
    for (auto& [_, child] : node->children) {
        children_list.push_back(child);
    }
    std::sort(children_list.begin(), children_list.end(), [](const auto& a, const auto& b) {
        return a->count > b->count;
    });

    for (size_t i = 0; i < children_list.size(); ++i) {
        print_ascii_tree(children_list[i], child_prefix, i == children_list.size() - 1);
    }
}

static void print_reverse_callgraph() {
    if (g_syscall_trees.empty()) {
        std::cout << "\n[!] Данные стека вызовов отсутствуют.\n";
        return;
    }

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
        for (auto& [_, child] : tree->children) {
            children_list.push_back(child);
        }
        std::sort(children_list.begin(), children_list.end(), [](const auto& a, const auto& b) {
            return a->count > b->count;
        });

        for (size_t i = 0; i < children_list.size(); ++i) {
            print_ascii_tree(children_list[i], "", i == children_list.size() - 1);
        }
        std::cout << "\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Генерация DOT файла (Graphviz)
// ─────────────────────────────────────────────────────────────────────────────

static void export_dot_node(std::ofstream& out, const std::shared_ptr<TreeNode>& parent, size_t& node_id) {
    size_t current_id = node_id;

    for (auto& [name, child] : parent->children) {
        size_t child_id = ++node_id;
        out << "  node" << current_id << " [label=\"" << parent->name << "\\n(" << parent->count << ")\"];\n";
        out << "  node" << child_id << " [label=\"" << child->name << "\\n(" << child->count << ")\"];\n";
        out << "  node" << current_id << " -> node" << child_id << " [label=\"" << child->count << "\"];\n";
        export_dot_node(out, child, node_id);
    }
}

static void export_graphviz_dot(const std::string& filename) {
    std::ofstream out(filename);
    if (!out.is_open()) return;

    out << "digraph ReverseCallGraph {\n";
    out << "  rankdir=LR;\n";
    out << "  node [shape=box, style=rounded, fontname=\"Helvetica\"];\n";
    out << "  edge [fontname=\"Helvetica\", fontsize=10];\n\n";

    size_t node_id = 0;
    for (auto& [name, tree] : g_syscall_trees) {
        export_dot_node(out, tree, node_id);
    }

    out << "}\n";
    std::cout << "[+] Экспортирован граф вызовов в файл: " << filename << "\n";
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

    std::cout << "[*] Запускаем дочерний процесс: " << argv[1] << "\n";

    g_target = fork();
    if (g_target < 0) {
        std::cerr << "[!] fork(): " << strerror(errno) << "\n";
        dtrace_close(g_dtp);
        return 1;
    }

    if (g_target == 0) {
        raise(SIGSTOP);
        execvp(argv[1], argv + 1);
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

    std::cout << "[*] Сбор стеков вызовов для PID " << g_target << "...\n";

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

    // Печатаем обратный граф вызовов
    print_reverse_callgraph();

    // Экспортируем в Graphviz DOT
    export_graphviz_dot("callgraph.dot");

    dtrace_close(g_dtp);

    if (kill(g_target, 0) == 0) {
        kill(g_target, SIGTERM);
        waitpid(g_target, nullptr, 0);
    }

    return 0;
}
