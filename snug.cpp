#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <array>
#include <mutex>
#include <shared_mutex>


#define SNUGSIZE 256ull*1024ull*1024ull*1024ull
#define BUCKET_COUNT 1048576

std::array<std::shared_mutex, BUCKET_COUNT> mutexes;

// 0 = success
// 1 = could not open
// 2 = could not seek
// 3 = could not write at end of file
int alloc_file(char const* fn)
{
    int fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return 1;

    // must be a multiple of bufsize

    if (lseek(fd, SNUGSIZE - 1, SEEK_SET) == -1)
    {
        close(fd);
        unlink(fn);
        return 2;
    }

    if (write(fd, "", 1) != 1)
    {
        close(fd);
        unlink(fn);
        return 3;
    }

    close(fd);
    return 0;
}

#define OFFSET(byte0, byte1, byte2)\
    (((((uint64_t)(byte0 & 0xFFU)) << 12) +\
    (((uint64_t)(byte1 & 0xFFU)) << 4) +\
    ((uint64_t)(byte2 & 0xFU))) << 18)

// 0 = file exists and is right size
int check_file(char const* fn)
{
    struct stat st;
    int file_exists = (stat(fn, &st) == 0);

    if (!file_exists)
        return 1;

    if (st.st_size != SNUGSIZE)
        return 2;

    return 0;
}


// check if 32 bytes are 0, which they will be for a zero entry
#define IS_ZERO_ENTRY(x)\
    (*((uint64_t*)((x)+ 0)) == 0 && \
    *((uint64_t*)((x)+ 8)) == 0 && \
    *((uint64_t*)((x)+16)) == 0 && \
    *((uint64_t*)((x)+24)) == 0)

#define IS_ENTRY(x,y)\
    (*((uint64_t*)((x)+ 0)) == *((uint64_t*)((y)+ 0)) && \
    *((uint64_t*)((x)+ 8)) == *((uint64_t*)((y)+ 8)) && \
    *((uint64_t*)((x)+16)) == *((uint64_t*)((y)+16)) && \
    *((uint64_t*)((x)+24)) == *((uint64_t*)((y)+24)))

#define WRITE_KEY(x /* dst */, y /* src */, flags)\
{\
    *((uint64_t*)((x)+ 0)) = *((uint64_t*)((y)+ 0)); \
    *((uint64_t*)((x)+ 8)) = *((uint64_t*)((y)+ 8)); \
    *((uint64_t*)((x)+16)) = *((uint64_t*)((y)+16)); \
    *((uint64_t*)((x)+24)) = *((uint64_t*)((y)+24)); \
    *((uint64_t*)((x)+32)) = flags;\
}


/*
 * Entry format:
 * 0    - 31: the 32 byte key
 * 32   - 39: flags (high 4 bytes are flags, low 4 are size)
 * 40 - 1023: data (up to 984 bytes)
 */
// 0 = success
// 1 = bucket full
int write_entry(uint8_t* data, uint8_t* key, uint8_t* val, ssize_t len)
{
    // find the entry
    uint64_t offset = OFFSET(key[0], key[1], (key[2]>>4));

    // lock the bucket for writing
    std::unique_lock lock(mutexes[offset >> 18]);

    uint8_t* start = data + offset;
    for (int i = 0; i < 256*1024; i+=1024)
    {
        if (!IS_ENTRY(start + i, key) && !IS_ZERO_ENTRY(start + i))
            continue;    

        /// write entry

        // RH TODO: manage large val edge case
        WRITE_KEY(start + i, key, (len & 0xFFFFFFFFUL));
        memcpy(start + i + 40, val, len);

        return 0;
    }

    /// file (bucket) full
    return 1;
}

int read_entry(uint8_t* data, uint8_t* key, uint8_t* val_out, uint32_t max_out_len)
{
    // find the entry
    uint64_t offset = OFFSET(key[0], key[1], (key[2]>>4));

    // lock the bucket for reading
    std::shared_lock lock(mutexes[offset >> 18]);

    for (int i = 0; i < 256*1024; i+=1024)
    {
        if (IS_ZERO_ENTRY(start + i))
            return 0;


        if (!IS_ENTRY(start + i, key))
            continue;
        
        // read out the value
        // RH TODO: handle large val edge case

        uint64_t flags = *((uint64_t*)(start + i + 32));
        uint32_t size = flags & 0xFFFFFFFFUL;

        if (size > max_out_len)
            return 2;

        memcpy(val_out, start + i + 40, size);
        return 0;
    }

    return 1;
}

int main()
{
    char const* fn = "snug.1";

    if (check_file(fn))
    {
        fprintf(stderr, "File check failed, creating new file %s.\n", fn);
        int result = alloc_file(fn);
        if (result)
        {
            fprintf(stderr, "Could not create new file %s. Error=%d\n", fn, result);
            return 1;
        }
    }


    int fd = open(fn, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1)
    {
        perror("Error opening file");
        return 1;
    }

    void *mapped = mmap(NULL, SNUGSIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED)
    {
        perror("Error mapping file");
        close(fd);
        return 1;
    }

    // successfully mapped
    
    uint8_t* data = (uint8_t*)mapped;
    uint8_t key[]{
            0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,
            0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,
            0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,
            0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB};

    uint8_t val[] {0xDE, 0xAD, 0xBE, 0xEF};
    write_entry(data, key, val, 4);
   /*
    data[0] = 'A';
    printf("First byte: %c\n", data[0]);

    
    data[OFFSET(0xCA, 0xFE, 0xB)] = 'B';

    data[OFFSET(0xFF, 0xFF, 0xF) + 256*1024 - 1] = 'Z';

    printf("last: %08X\n", OFFSET(0xFF, 0xFF, 0xF) + 256*1024 - 1);
*/
    if (munmap(mapped, SNUGSIZE) == -1)
    {
        perror("Error unmapping file");
    }

    close(fd);
    return 0;
}
