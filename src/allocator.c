#include <stddef.h> // Забезпечує визначення базових типів даних, таких як size_t
#include <stdio.h>  // Стандартна бібліотека вводу/виводу

#include "allocator.h"  // Включає оголошення функцій вашого розподільника
#include "block.h"      //  містить визначення структур блоків
#include "config.h"     //  містить значення конфігурації
#include "kernel.h"     // Може взаємодіяти з ядром ОС для виділення пам'яті

// Глобальна змінна для зберігання виділеної арени пам'яті
static struct block *arena = NULL;

// Визначення розміру арени на основі значень конфігурації
#define ARENA_SIZE (ALLOCATOR_ARENA_PAGES * ALLOCATOR_PAGE_SIZE)

// Визначення максимального розміру блоку в арені (з урахуванням розміру структури блоку)
#define BLOCK_SIZE_MAX (ARENA_SIZE - BLOCK_STRUCT_SIZE)

static int
arena_alloc(void)
{
    // Виділення пам'яті для арени за допомогою функції ядра (виділення пам'яті ОС)
    arena = kernel_alloc(ARENA_SIZE);
    if (arena != NULL) {
        // Ініціалізація арени (налаштовує перший блок і метадані)
        arena_init(arena, ARENA_SIZE - BLOCK_STRUCT_SIZE);
        return 0; // Успіх
    }
    return -1; // Помилка
}

void *
mem_alloc(size_t size)
{
    struct block *block;

    // Перевірка, чи арена ще не виділена
    if (arena == NULL) {
        // Спробувати виділити арену, якщо вона ще не створена
        if (arena_alloc() < 0)
            return NULL; // Виділення не вдалося
    }

    // Перевірка, чи запитуваний розмір більший за максимальний розмір блоку
    if (size > BLOCK_SIZE_MAX)
        return NULL; // Розмір занадто великий для цього розподільника

    // Округлення розміру до певної вимоги вирівнювання (реалізація в ROUND_BYTES)
    size = ROUND_BYTES(size);

    // Цикл по блоках в арені
    for (block = arena;; block = block_next(block)) {
        // Перевірити, чи поточний блок вільний і має достатньо місця для запиту
        if (!block_get_flag_busy(block) && block_get_size_curr(block) >= size) {
            // Розділити блок, якщо потрібно, щоб розмістити запит (реалізація в block_split)
            block_split(block, size);
            // Повернути вказівник на виділені дані всередині блоку (реалізація в block_to_payload)
            return block_to_payload(block);
        }

        // Вийти з циклу, якщо поточний блок є останнім
        if (block_get_flag_last(block))
            break;
    }

    // Не знайдено відповідного блоку, повернути NULL
    return NULL;
}

void
mem_free(void *ptr)
{
    struct block *block, *block_r, *block_l;

    // Обробити випадок нульового вказівника (немає чого звільняти)
    if (ptr == NULL)
        return;

    // Перетворити вказівник на структуру блоку
    block = payload_to_block(ptr);

    // Позначити блок як вільний
    block_clr_flag_busy(block);

    // Перевірити, чи блок не є останнім
    if (!block_get_flag_last(block)) {
        // Отримати наступний блок
        block_r = block_next(block);
        // Якщо наступний блок вільний, об'єднати їх
               // (реалізація в block_merge)
        if (!block_get_flag_busy(block_r))
            block_merge(block, block_r);
    }

    // Перевірити, чи блок не є першим
    if (!block_get_flag_first(block)) {
        // Отримати попередній блок
        block_l = block_prev(block);
        // Якщо попередній блок вільний, об'єднати їх
        // (реалізація в block_merge)
        if (!block_get_flag_busy(block_l))
            block_merge(block_l, block);
    }
}

void *
mem_realloc(void *ptr, size_t size) {
    // Якщо вказаний покажчик є NULL, виділяємо новий блок пам'яті заданого розміру
    if (ptr == NULL) return mem_alloc(size);

    // Отримуємо блок пам'яті, пов'язаний з вказаним покажчиком
    struct block *block = payload_to_block(ptr);

    // Перевіряємо, чи можна збільшити розмір поточного блоку
    size_t current_size = block_get_size_curr(block);
    // Якщо новий розмір менший або рівний поточному, просто повертаємо поточний покажчик
    if (size <= current_size) return ptr;

    // Визначаємо розмір розширеного блоку
    size_t new_size = ROUND_BYTES(size);

    // Визначаємо розмір, на який треба збільшити блок
    size_t increase = new_size - current_size;

    // Шукаємо наступний блок
    struct block *next_block = block_next(block);

    // Перевіряємо, чи наступний блок є вільним і чи можна розширити поточний блок
    if (!block_get_flag_last(block) && !block_get_flag_busy(next_block) && block_get_size_curr(next_block) >= increase) {
        // Розширюємо поточний блок, вільний простір відводимо на новий блок
        block_merge(block, next_block);
        block_split(block, new_size);
        return block_to_payload(block);
    } else {
        // Якщо не можна розширити поточний блок, виділяємо новий блок пам'яті потрібного розміру
        void *new_ptr = mem_alloc(size);
        if (new_ptr != NULL) {
            // Копіюємо дані з поточного блоку в новий
            memcpy(new_ptr, ptr, current_size);
            // Звільняємо поточний блок
            mem_free(ptr);
        }
        return new_ptr;
    }
}

void
mem_show(const char *msg)
{
    const struct block *block;

    printf("%s:\n", msg);
    if (arena == NULL) {
        printf("Арена не була створена\n");
        return;
    }

    // Цикл по блоках в арені
    for (block = arena;; block = block_next(block)) {
        printf("[%15p] %13zu | %13zu | %s%s%s \n",
            (void *)block,
            block_get_size_curr(block), block_get_size_prev(block),
            block_get_flag_busy(block) ? "занятий" : "вільний",
            block_get_flag_first(block) ? " перший " : "",
            block_get_flag_last(block) ? " останній" : "");
        if (block_get_flag_last(block))
            break;
    }
}