# syscall_counter & syscall_callgraph

Инструменты на C++ для анализа и построения **обратного графа вызовов (Reverse Call Graph)** системных вызовов процесса на macOS с использованием DTrace API.

---

## 📌 Компоненты

1. **`syscall_counter`** — Подсчитывает общее количество и процентное соотношение каждого системного вызова (syscall).
2. **`syscall_callgraph`** — Захватывает стек вызовов пользователей (`ustack`) и строит **обратное дерево вызовов (Reverse Call Graph)** в консоли, показывая цепь функций (функций библиотеки и функций пользователя), которые привели к каждому системному вызову, а также экспортирует граф в формат **Graphviz DOT** (`callgraph.dot`).

---

## 🛠 Требования

- macOS (macOS Big Sur, Monterey, Ventura, Sonoma, Sequoia и т.д.)
- Компилятор `clang++` с поддержкой C++17
- Права суперпользователя (`sudo`)

---

## 🚀 Сборка

```bash
make
```

Будут собраны утилиты `syscall_counter` и `syscall_callgraph`.

---

## 💻 Использование

### 1. Подсчёт системных вызовов (`syscall_counter`)

```bash
sudo ./syscall_counter /bin/ls -la /tmp
```

### 2. Построение Обратного Графа Вызовов (`syscall_callgraph`)

```bash
sudo ./syscall_callgraph /bin/ls -la /tmp
```

---

## 📊 Пример вывода обратного графа (`syscall_callgraph`)

```text
===============================================================
       ОБРАТНЫЙ ГРАФ / ДЕРЕВО ВЫЗОВОВ (REVERSE CALL GRAPH)      
       [ Syscall -> Calling Stack Frames -> Main / Caller ]     
===============================================================

SYSCALL: open_nocancel (всего: 18 вызовов)
├── libsystem_kernel.dylib`__open_nocancel [18 calls]
│   └── libsystem_info.dylib`si_open [12 calls]
│       └── libsystem_info.dylib`si_module_config [12 calls]
│           └── /bin/ls`main [12 calls]
│   └── libsystem_c.dylib`opendir [6 calls]
│       └── /bin/ls`printcol [6 calls]

SYSCALL: read (всего: 87 вызовов)
├── libsystem_kernel.dylib`read [87 calls]
│   └── libsystem_c.dylib`__srefill [80 calls]
│       └── libsystem_c.dylib`fgets [80 calls]
│           └── /bin/ls`main [80 calls]

[+] Экспортирован граф вызовов в файл: callgraph.dot
```

---

## 🎨 Визуализация графа (Graphviz)

Сгенерированный файл `callgraph.dot` можно визуализировать в SVG/PNG с помощью утилиты `dot`:

```bash
brew install graphviz
dot -Tpng callgraph.dot -o callgraph.png
```

---

## ⚠️ Замечания по безопасности (SIP)

На macOS DTrace подпадает под ограничения System Integrity Protection (SIP). В случае проблем с доступом DTrace может потребоваться включить разрешение для DTrace в режиме восстановления (Recovery Mode):

```bash
csrutil enable --without dtrace
```

---

## 📄 Лицензия

MIT
