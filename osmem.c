// SPDX-License-Identifier: BSD-3-Clause
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include "osmem.h"
#include "block_meta.h"
#include "string.h"
#define MIN_BLOCK_SIZE sizeof(struct block_meta)
#define MMAP_THRESHOLD (128 * 1024)

static struct block_meta *List;
static struct block_meta *pointer;
size_t remaining_heap_size;
void *heap_head;

void init_heap(void)
{
	heap_head = sbrk(MMAP_THRESHOLD);
	remaining_heap_size = MMAP_THRESHOLD;
}

void split_block(struct block_meta *block, size_t size)
{
	size_t total_size = (1 + sizeof(struct block_meta) + 7) & ~7;

	if (block->size - size >= total_size) {
		struct block_meta *new_block = (struct block_meta *)((char *)block + size);

		new_block->size = block->size - size;
		new_block->status = 0;
		new_block->prev = block;
		new_block->next = block->next;
		if (block->next != NULL)
			block->next->prev = new_block;
		block->size = size;
		block->next = new_block;
		if (new_block->next == NULL)
			pointer = new_block;
		block->size = size;
	}
}

void coalesce_block(struct block_meta *block)
{
	if (block->next != NULL && block->next->status == 0) {
		// Merge with the next free block
		block->size += block->next->size + sizeof(struct block_meta);

		block->next = block->next->next;

		if (block->next)
			block->next->prev = block;
	}

	if (block->prev != NULL && block->prev->status == 0) {
		// Merge with the previous free block
		block->prev->size += block->size + sizeof(struct block_meta);
		block->prev->next = block->next;

		if (block->next)
			block->next->prev = block->prev;
	}
}

struct block_meta *find_fit(size_t size)
{
	struct block_meta *best_fit = NULL;
	static struct block_meta *ptr;
	size_t min_size = (size_t) -1;

	ptr = List;
	while (ptr != NULL) {
		if (ptr->size >= size && ptr->status == 0 && ptr->size < min_size) {
			min_size = ptr->size;
			best_fit = ptr;
		}
		ptr = ptr->next;
	}
	return best_fit;
}

void *allocate_large(size_t size)
{
	size_t total_size = (size + sizeof(struct block_meta) + 7) & ~7;
	void *ptr = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	struct block_meta *meta = (struct block_meta *)ptr;

	if (List == NULL) {
		List = meta;
		pointer = meta;
		meta->size = total_size;
		meta->status = STATUS_MAPPED; // Allocated
		meta->prev = NULL;
		meta->next = NULL;
	} else {
		meta->size = total_size;
		meta->status = STATUS_MAPPED; // Allocated
		meta->prev = pointer;
		meta->next = NULL;
		pointer->next = meta;
		pointer = meta;
	}
	return (void *)(meta + 1);
}

void *allocate_small(size_t size)
{
	size_t total_size = (size + sizeof(struct block_meta) + 7) & ~7;
	void *ptr = NULL;
	struct block_meta *new_ptr = find_fit(total_size);

	if (new_ptr == NULL) {
		if (total_size > remaining_heap_size) {
			if (pointer->status == 0) {
				ptr = sbrk((total_size - pointer->size + 7) & ~7);
				pointer->status = 1;
				pointer->size = total_size;
				return (void *)(pointer + 1);
			}
			ptr = sbrk(total_size);
		} else {
			ptr = heap_head;
			remaining_heap_size = remaining_heap_size - total_size;
			heap_head += total_size;
		}
		struct block_meta *meta = (struct block_meta *)ptr;

		if (List == NULL) {
			List = meta;
			pointer = meta;
			meta->size = total_size;
			meta->status = 1; // Allocated
			meta->prev = NULL;
			meta->next = NULL;
		} else {
			meta->size = total_size;
			meta->status = 1; // Allocated
			meta->prev = pointer;
			meta->next = NULL;
			pointer->next = meta;
			pointer = meta;
		}
		return (void *)(meta + 1);
	}
	split_block(new_ptr, total_size);
	new_ptr->status = 1; // Allocated
	return (void *)(new_ptr + 1);
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	if (size == 0)
		return NULL;
	if (heap_head == NULL && size < MMAP_THRESHOLD)
		init_heap();
	if (size >= MMAP_THRESHOLD)
		return allocate_large(size);
	return allocate_small(size);
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (!ptr)
		return;
	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->status == 1) {
		block->status = 0;
		coalesce_block(block);
	}
	if (block->status == 2)
		munmap(block, block->size);
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	size_t total_size = nmemb * size;
	size_t al_size = (total_size + sizeof(struct block_meta) + 7) & ~7;
	void *ptr = NULL;

	if (size == 0 || nmemb == 0)
		return NULL;
	if (heap_head == NULL && al_size < (size_t)getpagesize())
		init_heap();
	if (total_size >= (size_t)getpagesize())
		ptr = allocate_large(total_size);
	else
		ptr = allocate_small(total_size);
	if (ptr != NULL)
		memset(ptr, 0, total_size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	if (ptr == NULL)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->status == STATUS_FREE)
		return NULL;
	if (size < block->size)
		return ptr;

	size_t total_size = (size + sizeof(struct block_meta) + 7) & ~7;
	size_t current_block_size = block->size;

	if (block->next != NULL && block->next->status == STATUS_FREE &&
(current_block_size + sizeof(struct block_meta) + block->next->size) >= total_size) {
		block->size = current_block_size + sizeof(struct block_meta) + block->next->size;
		block->next = block->next->next;

		if (block->next)
			block->next->prev = block;

		split_block(block, size);
		return block;
	}
	if (block->status == 1)
		block->status = 0;
	if (block->status == 2)
		munmap(block, block->size);
	void *new_ptr = os_malloc(size);

	if (new_ptr != NULL) {
		os_free(ptr);
		memcpy(new_ptr, ptr, block->size);
	}
	return new_ptr;
}
