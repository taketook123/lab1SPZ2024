#include "block.h"  // Include the header file for block definitions

void
block_split(struct block *block, size_t size)
{
    // This function splits a block into two smaller blocks.
    // 'block' - pointer to the block to be split
    // 'size' - size of the first block to be allocated

    struct block *block_r;  // pointer to the right block after split
    size_t size_rest;        // size of the remaining block after split

    // Calculate the remaining size after allocating 'size' bytes
    size_rest = block_get_size_curr(block) - size;

    // Check if there's enough space to create another block (at least the size of the block structure)
    if (size_rest >= BLOCK_STRUCT_SIZE) {
        size_rest -= BLOCK_STRUCT_SIZE; // Adjust remaining size to account for block structure overhead

        // Set the size of the current block (the one being allocated from)
        block_set_size_curr(block, size);

        // Get a pointer to the block to the right after splitting (split point)
        block_r = block_next(block);

        // Initialize the right block metadata
        block_init(block_r);

        // Set the size of the right block (remaining space)
        block_set_size_curr(block_r, size_rest);

        // Set the size of the previous block for the right block (current block size)
        block_set_size_prev(block_r, size);

        // Update last block flag if the current block was the last one
        if (block_get_flag_last(block)) {
            block_clr_flag_last(block); // Clear last block flag for current block
            block_set_flag_last(block_r); // Set last block flag for right block
        } else {
            // Update previous block's size_prev if not the last block
            block_set_size_prev(block_next(block_r), size_rest);
        }
    }

    // Set the busy flag of the allocated block
    block_set_flag_busy(block);
}

void
block_merge(struct block *block, struct block *block_r)
{
    // This function merges two adjacent blocks into a single block.
    // 'block' - pointer to the first block
    // 'block_r' - pointer to the right block to be merged

    size_t size;  // total size of the merged block

    // Calculate the total size of the merged block
    size = block_get_size_curr(block) + block_get_size_curr(block_r) +
          BLOCK_STRUCT_SIZE; // Include block structure overhead

    // Set the size of the first block to the total size
    block_set_size_curr(block, size);

    // Update last block flag based on the right block's flag
    if (block_get_flag_last(block_r))
        block_set_flag_last(block); // Set last block flag if the right block was last
    else
        block_set_size_prev(block_next(block_r), size); // Update previous block size if not last

}