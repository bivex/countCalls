# macOS Syscall Tracing & Call Graph Tools

Инструменты на C++ для анализа системных вызовов процесса на macOS через DTrace API с поддержкой форматов вывода для **LLM** (JSON / Markdown) и человека (ASCII Tree / Table / Graphviz).

---

## 🚀 Форматы вывода

Каждая утилита поддерживает флаги для удобного взаимодействия с LLM (Large Language Models):

| Флаг | Формат | Описание |
|---|---|---|
| `--json` | **JSON** | Чистый структурированный JSON для парсинга и передачи в LLM API |
| `--markdown` / `--llm` | **Markdown** | Чистый список в формате Markdown (без ASCII-рамки) |
| `--tree` / `--table` | **ASCII** | Табличный или древовидный вид для человека в терминале |

---

## 🛠 Использование

### 1. Обратный граф вызовов (`syscall_callgraph`)

#### Вывод в формате JSON (для LLM):
```bash
sudo ./syscall_callgraph --json /bin/ls -la /tmp
```
**Пример вывода:**
```json
{
  "target": "/bin/ls",
  "pid": 45120,
  "unique_syscalls": 23,
  "syscalls": [
    {
      "syscall": "open_nocancel",
      "total_calls": 18,
      "tree": [
        {
          "name": "libsystem_kernel.dylib`__open_nocancel",
          "count": 18,
          "children": [
            {
              "name": "libsystem_info.dylib`si_open",
              "count": 12,
              "children": [
                {
                  "name": "/bin/ls`main",
                  "count": 12
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

#### Вывод в формате Markdown (для LLM):
```bash
sudo ./syscall_callgraph --markdown /bin/ls -la /tmp
```

#### Вывод в формате ASCII дерева (в терминал):
```bash
sudo ./syscall_callgraph --tree /bin/ls -la /tmp
```

---

### 2. Сводная статистика системных вызовов (`syscall_counter`)

#### Вывод в формате JSON (для LLM):
```bash
sudo ./syscall_counter --json /bin/ls -la /tmp
```

#### Вывод в формате Markdown (для LLM):
```bash
sudo ./syscall_counter --markdown /bin/ls -la /tmp
```

---

## ⚙️ Сборка

```bash
make
```

---

## 📄 Лицензия

MIT
