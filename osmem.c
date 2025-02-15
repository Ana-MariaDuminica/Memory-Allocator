// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "block_meta.h"

#define THRESHOLD (128 * 1024)
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define blocksize (ALIGN(sizeof(struct block_meta)))

static int first_heap_allocation = 1;
static struct block_meta *head;

void delete_block(struct block_meta **head, struct block_meta *to_delete)
{
	if (*head == NULL)
		return;

	if (*head == to_delete) {
		*head = to_delete->next;
	} else {
		struct block_meta *current = *head;

		while (current->next != NULL && current->next != to_delete)
			current = current->next;

		if (current->next != NULL)
			current->next = to_delete->next;
	}
}

void add_block(struct block_meta *block)
{
	if (head == NULL) {
		head = block;
		block->prev = NULL;
		block->next = NULL;
		return;
	}

	struct block_meta *last_heap_block = NULL;
	struct block_meta *current = head;

	while (current) {
		if (current->status != 1)
			break;

		last_heap_block = current;
		current = current->next;
	}

	if (last_heap_block) {
		block->prev = last_heap_block;
		block->next = last_heap_block->next;

		if (last_heap_block->next)
			last_heap_block->next->prev = block;

		last_heap_block->next = block;
	} else {
		block->next = head;
		if (head)
			head->prev = block;

		head = block;
		block->prev = NULL;
	}
}

void merge_free_blocks(void)
{
	struct block_meta *current = head;

	while (current->next) {
		if (current->status == 0 && current->next->status == 0) {
			current->size += current->next->size + blocksize;
			current->next = current->next->next;

			if (current->next)
				current->next->prev = current;
		} else {
			current = current->next;
		}
	}
}

void *mmap_alloc(size_t size)
{
	// Allocate memory using mmap
	void *ptr = mmap(NULL, size + blocksize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (ptr == MAP_FAILED)
		return NULL;

	struct block_meta *block = (struct block_meta *)ptr;

	block->size = size;
	block->status = 2;
	add_block(block);

	return (void *)(block + 1);
}

void *heap_alloc(size_t size, size_t threshold)
{
	if (first_heap_allocation) {
		// Perform heap preallocation
		void *heap_start = sbrk(threshold);

		if (heap_start == (void *)-1)
			return NULL;

		struct block_meta *block = (struct block_meta *)heap_start;

		block->size = threshold - blocksize;
		block->status = 1;
		block->next = NULL;

		add_block(block);
		first_heap_allocation = 0;

		return (void *)(block + 1);
	}
	// Merge consecutive free blocks
	merge_free_blocks();

	struct block_meta *current = head;
	struct block_meta *block = NULL;

	// Find best block in size
	while (current) {
		if (current->status == 0 && current->size >= size) {
			if (block == NULL || current->size < block->size)
				block = current;
		}
		current = current->next;
	}

	if (block != NULL) {
		block->status = 1;
		// Split the best free block if it's larger than the needed size
		if (block->size > size + blocksize) {
			struct block_meta *new_block = (struct block_meta *)((char *)block + size + blocksize);

			new_block->size = block->size - size - blocksize;
			new_block->status = 0;
			new_block->next = block->next;

			block->size = size;
			block->next = new_block;
			block->status = 1;
		}

		return (void *)(block + 1);
	}

	// Expand the last block on the heap
	struct block_meta *curr = head;

	while (curr->next != NULL) {
		if (curr->next->status == 2)
			break;
		curr = curr->next;
	}

	if (curr != NULL) {
		if (curr->status == 0) {
			void *heap_all = sbrk(size - curr->size);

			if (heap_all == (void *)-1)
				return NULL;

			curr->size = size;
			curr->status = 1;
			curr->next = NULL;

			return (void *)(curr + 1);
		}
	}

	// Allocate additional memory with sbrk
	size_t block_size = size + blocksize;
	void *heap_alloc = sbrk(block_size);

	if (heap_alloc == (void *)-1)
		return NULL;

	struct block_meta *finalblock = (struct block_meta *)heap_alloc;

	finalblock->size = size;
	finalblock->status = 1;
	finalblock->next = NULL;

	add_block(finalblock);

	return (void *)(finalblock + 1);
}

void *os_malloc(size_t size)
{
	size = ALIGN(size);

	if (size == 0)
		return NULL;

	if (size + blocksize >= THRESHOLD) {
		// Allocate memory using mmap
		struct block_meta *block = mmap_alloc(size);

		return (void *)(block);
	}
	// Allocate memory on the heap
	struct block_meta *block = heap_alloc(size, THRESHOLD);

	return (void *)(block);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->status == 1)
		block->status = 0;

	if (block->status == 2) {
		block->status = 0;
		delete_block(&head, block);
		munmap(block, block->size + blocksize);
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	if (nmemb == 0 || size == 0)
		return NULL;

	size_t aligned_size = ALIGN(nmemb * size);

	if (aligned_size + blocksize >= (size_t)getpagesize()) {
		void *ptr = mmap_alloc(aligned_size);

		memset(ptr, 0, aligned_size);
		return ptr;

	} else {
		void *ptr = heap_alloc(aligned_size, THRESHOLD);

		memset(ptr, 0, aligned_size);
		return ptr;
	}
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->status == 0)
		return NULL;

	size_t aligned_size = ALIGN(size);

	if (aligned_size == block->size)
		return ptr;

	if (block->status == 2) {
		// Block was initially allocated with mmap
		void *new_ptr = os_malloc(aligned_size);

		if (new_ptr == NULL)
			return NULL;

		if (block->size < aligned_size)
			aligned_size = block->size;

		memcpy(new_ptr, ptr, aligned_size);
		os_free(ptr);
		return new_ptr;
	}

	// Addresses on the heap
	if (aligned_size < block->size) {
		// New size is smaller
		if (block->size > aligned_size + blocksize) {
			struct block_meta *new_block = (struct block_meta *)((char *)block + aligned_size + blocksize);

			new_block->size = block->size - aligned_size - blocksize;
			new_block->status = 0;
			new_block->next = block->next;

			block->size = aligned_size;
			block->next = new_block;
			block->status = 1;
		}
		return (void *)(block + 1);

	} else {
		// New size is bigger
		struct block_meta *curr = block->next;

		// if the block is the last one on the heap we can expand that one
		if (block->next == NULL) {
			void *heap_all = sbrk(aligned_size - block->size);

			if (heap_all == (void *)-1)
				return NULL;

			block->size = aligned_size;
			block->status = 1;
			block->next = NULL;

			return (void *)(block + 1);
		}

		while (curr != NULL && curr->status == 0) {
			// Coalesce consecutive free blocks
			block->size += curr->size + blocksize;
			block->next = curr->next;

			if (block->size >= aligned_size) {
				// Split the block if necessary
				if (block->size > aligned_size + blocksize) {
					struct block_meta *new_block = (struct block_meta *)((char *)block + aligned_size + blocksize);

					new_block->size = block->size - aligned_size - blocksize;
					new_block->status = 0;
					new_block->next = block->next;

					block->size = aligned_size;
					block->next = new_block;
					block->status = 1;
				}
				return (void *)(block + 1);
			}
			curr = curr->next;
		}

		// Allocate a new block
		void *new_ptr = os_malloc(size);

		if (new_ptr == NULL)
			return NULL;

		if (block->size < aligned_size)
			aligned_size = block->size;

		memcpy(new_ptr, ptr, aligned_size);
		os_free(ptr);
		return new_ptr;
	}

	return NULL;
}
