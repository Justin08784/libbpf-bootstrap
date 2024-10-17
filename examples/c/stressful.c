#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>

#define ARR_SIZE 2<<29
int main()
{
    size_t *memory = malloc(sizeof(size_t) * ARR_SIZE);

    assert(mlock(memory, sizeof(size_t)*ARR_SIZE));

    printf("Starting writes...\n");
    while (1) {
        // touch all pages sequentially
        for (size_t i = 0; i < ARR_SIZE; ++i)
            memory[i] = i;
    }
}
