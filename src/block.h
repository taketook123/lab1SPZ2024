#include <stdbool.h>  // Include for boolean data type

#include "allocator_impl.h" // Likely contains private implementation details

struct block {
    size_t size_curr;  // Current size of the block (allocated data)
    size_t size_prev;  // Size of the previous block (for bookkeeping)
    bool flag_busy;    // Flag indicating if the block is currently allocated
    bool flag_first;   // Flag indicating if the block is the first block in the arena
    bool flag_last;    // Flag indicating if the block is the last block in the arena
};

#define BLOCK_STRUCT_SIZE ROUND_BYTES(sizeof(struct block))  // Define block structure size with rounding

// Function prototypes for block manipulation functions
void block_split(struct block *, size_t);
void block_merge(struct block *, struct block *);

// Helper functions for manipulating block data (likely implemented elsewhere)
static inline void *
block_to_payload(const struct block *block)
{
    return (char *)block + BLOCK_STRUCT_SIZE; // Return pointer to data area within the block
}

static inline struct block *
payload_to_block(const void *ptr)
{
    return (struct block *)((char *)ptr - BLOCK_STRUCT_SIZE); // Return pointer to block structure from data area
}

static inline void
block_set_size_curr(struct block *block, size_t size)
{
    block->size_curr = size; // Set the current size of the block
}

static inline size_t
block_get_size_curr(const struct block *block)
{
    return block->size_curr; // Get the current size of the block
}

static inline void
block_set_size_prev(struct block *block, size_t size)
{
    block->size_prev = size; // Set the size of the previous block
}

static inline size_t
block_get_size_prev(const struct block *block)
{
    return block->size_prev; // Get the size of the previous block
}

static inline void
block_set_flag_busy(struct block *block)
{
    block->flag_busy = true; // Set the busy flag to true (allocated)
}

static inline bool
block_get_flag_busy(const struct block *block)
{
    return block->flag_busy; // Get the busy flag (allocated or free)
}

static inline void
block_clr_flag_busy(struct block *block)
{
    block->flag_busy = false; // Set the busy flag to false (free)
}

static inline void
block_set_flag_first(struct block *block)
{
    block->flag_first = true; // Set the first block flag
}

static inline bool
block_get_flag_first(const struct block *block)
{
    return block->flag_first; // Get the first block flag
}

static inline void
block_set_flag_last(struct block *block)
{
    block->flag_last = true; // Set the last block flag
}

static inline bool
block_get_flag_last(const struct block *block)
{
    return block->flag_last; // Get the last block flag
}

static inline void
block_clr_flag_last(struct block *block)
{
    block->flag_last = false; // Clear the last block flag
}

static inline struct block *
block_next(const struct block *block)
{
    return (struct block *)
        ((char *)block + BLOCK_STRUCT_SIZE + block_get_size_curr(block)); // Get pointer to the next block
}

static inline struct block *
block_prev(const struct block *block)
{
    return (struct block *)
        ((char *)block - BLOCK_STRUCT_SIZE - block_get_size_prev(block)); // Get pointer to the previous block
}

static inline void
arena_init(struct block *block, size_t size)
{
    // Function to initialize the first block in the arena (likely implemented elsewhere)
    block->size_curr = size;
    block->size_prev = 0;
    block->flag_busy = false;
    block->flag_first = true;
    block->flag_last = true;
}

static inline void
block_init(struct block *block)
{
    // Function to initialize a new block (likely implemented elsewhere)
    block->flag_busy = false;
    block->flag_first = false;
    block->flag_last = false;
}