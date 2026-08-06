/**
 * demo_app.cpp
 *
 * Демонстрационная тестовая программа для проверки работы syscall_counter и syscall_callgraph.
 * Выполняет предсказуемые системные вызовы:
 * - Файловый В/В (open, write, read, close, unlink)
 * - Управление памятью (mmap, mprotect, munmap)
 */

#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

void perform_file_io() {
    std::cout << "  -> Выполняем файловые операции (open, write, read, close, unlink)...\n";
    int fd = open("/tmp/countcalls_demo.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd >= 0) {
        const char msg[] = "Hello Syscall Counter & CallGraph Demo!\n";
        write(fd, msg, sizeof(msg) - 1);
        lseek(fd, 0, SEEK_SET);
        char buf[64] = {0};
        read(fd, buf, sizeof(buf));
        close(fd);
        unlink("/tmp/countcalls_demo.txt");
    }
}

void perform_memory_ops() {
    std::cout << "  -> Выполняем операции с памятью (mmap, mprotect, munmap)...\n";
    size_t size = 4096;
    void* ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (ptr != MAP_FAILED) {
        mprotect(ptr, size, PROT_READ);
        munmap(ptr, size);
    }
}

int main() {
    std::cout << "[Demo App] Старт выполнения...\n";
    perform_file_io();
    perform_memory_ops();
    std::cout << "[Demo App] Завершено успешно.\n";
    return 0;
}
