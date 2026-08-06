/**
 * thread_spam_demo.cpp
 *
 * Демонстрация анти-паттерна THREAD_SPAM:
 * Создание 25 сырых ОС-потоков в цикле вместо использования Пул Потоков (Thread Pool).
 */

#include <iostream>
#include <thread>
#include <vector>
#include <unistd.h>

void do_work() {
    usleep(1000);
}

void spawn_raw_threads() {
    usleep(50000);
    std::vector<std::thread> threads;
    for (int i = 0; i < 25; ++i) {
        threads.emplace_back(do_work);
    }
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
}

int main() {
    spawn_raw_threads();
    usleep(100000);
    return 0;
}
