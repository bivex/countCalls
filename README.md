# macOS Syscall Tracing & Call Graph Tools

Инструменты на C++ для анализа системных вызовов процесса на macOS через DTrace API с поддержкой форматов вывода для **LLM** (JSON / Markdown) и человека (ASCII Tree / Table / Graphviz).

---

## 📌 Состав проекта

1. **`syscall_counter`** — Подсчитывает общее количество и процентное соотношение каждого системного вызова (syscall).
2. **`syscall_callgraph`** — Захватывает стек вызовов пользователей (`ustack`) и строит **обратное дерево вызовов (Reverse Call Graph)** в консоли (ASCII/Markdown/JSON/Graphviz DOT).
3. **`demo_app`** — Демонстрационная программа, выполняющая файловые операции (`open`, `write`, `read`, `close`, `unlink`) и управление памятью (`mmap`, `mprotect`, `munmap`).

---

## 🚀 Форматы вывода

Каждая утилита поддерживает флаги для удобного взаимодействия с LLM (Large Language Models):

| Флаг | Формат | Описание |
|---|---|---|
| `--json` | **JSON** | Чистый структурированный JSON для парсинга и передачи в LLM API |
| `--markdown` / `--llm` | **Markdown** | Чистый список в формате Markdown (без ASCII-рамки) |
| `--tree` / `--table` | **ASCII** | Табличный или древовидный вид для человека в терминале |

---

## 🛠 Использование и Тестирование

### Запуск демо-программы через `syscall_counter`:
```bash
sudo ./syscall_counter ./demo_app
```

### Запуск демо-программы через `syscall_callgraph` (в формате JSON):
```bash
sudo ./syscall_callgraph --json ./demo_app
```

### Запуск демо-программы через `syscall_callgraph` (в формате Markdown):
```bash
sudo ./syscall_callgraph --markdown ./demo_app
```

---

## ⚙️ Сборка

```bash
make
```

---

## 📄 Лицензия

MIT
