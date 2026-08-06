/**
 * memory_thrashing_demo.cpp
 *
 * Демонстрация анти-паттерна MEMORY_THRASHING:
 * 100 неоптимизированных вызовов mmap/munmap в цикле вместо использования
 * переиспользуемого буфера или Arena-Аллокатора.
 */

#include <unistd.h>
#include <sys/mman.h>

void thrash_memory() {
    usleep(50000);
    for (int i = 0; i < 100; ++i) {
        void* ptr = mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (ptr != MAP_FAILED) {
            munmap(ptr, 4096);
        }
    }
}

int main() {
    thrash_memory();
    usleep(100000);
    return 0;
}
