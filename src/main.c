#include <stdint.h> // Типи даних
#include <stdio.h> // Функції вводу-виводу
#include <stdlib.h> // Функції стандартної бібліотеки
#include <time.h> // Функції для роботи з часом

#include "allocator.h" // Заголовок вашого алокатора
#include "tester.h" // Заголовок для тестування алокатора

// Функція для виділення та заповнення буфера
static void *
buf_alloc(size_t size)
{
    char *buf;
    size_t i;

    // Виділення пам'яті
    buf = mem_alloc(size);

    // Перевірка успішного виділення
    if (buf != NULL) {
        // Заповнення буфера випадковими даними
        for (i = 0; i < size; ++i)
            buf[i] = (char)rand();
    }

    return buf;
}

int
main(void)
{

    void *ptr1, *ptr2, *ptr3;

    // Виділення максимально можливого блоку
    buf_alloc(SIZE_MAX);

    // Вивід інформації про стан алокатора
    mem_show("Initial");

    // Виділення блоку розміром 1 байт
    ptr1 = buf_alloc(1);

    // Вивід інформації про стан алокатора
    mem_show("alloc(1)");

    // Виділення блоку розміром 100 байт
    ptr2 = buf_alloc(100);

    // Вивід інформації про стан алокатора
    mem_show("alloc(100)");

    // Виділення блоку розміром 30 байт
    ptr3 = buf_alloc(30);

    // Вивід інформації про стан алокатора
    mem_show("alloc(30)");

    mem_realloc(ptr3, 34);

    mem_show("mem_realloc(ptr3, 150)");

    // Звільнення блоку ptr1
    mem_free(ptr1);

    // Вивід інформації про стан алокатора
    mem_show("free(ptr1)");

    // Звільнення блоку ptr2
    mem_free(ptr2);

    // Вивід інформації про стан алокатора
    mem_show("free(ptr2)");

    // Звільнення блоку ptr3
    mem_free(ptr3);

    // Вивід інформації про стан алокатора
    mem_show("free(ptr3)");

    // // Ініціалізація генератора випадкових чисел
    // srand(100/*(unsigned int)time(NULL)*/);

    // // Запуск тестів алокатора
    // tester(true);
}
