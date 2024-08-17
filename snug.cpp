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
#include <vector>
#include <memory>

class SnugDB
{

private:
    static constexpr uint64_t SNUGSIZE = 256ull*1024ull*1024ull*1024ull;
    static constexpr size_t BUCKET_COUNT = 1048576;

    std::unique_ptr<std::shared_mutex[]> mutexes = 
        std::make_unique<std::shared_mutex[]>(BUCKET_COUNT);


    // each file snug.0 snug.1 ... is mmaped and the pointer
    uint8_t* mapped_files[1024];
    uint64_t mapped_files_count { 0 };

    // only used when adding a new file
    std::mutex mapped_files_count_mutex;

    std::string const path;

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

#define OFFSET(byte0, byte1, byte2)\
        (((((uint64_t)(byte0 & 0xFFU)) << 12) +\
        (((uint64_t)(byte1 & 0xFFU)) << 4) +\
        ((uint64_t)(byte2 & 0xFU))) << 18)


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
    int write_entry_internal(uint8_t* data, uint8_t* key, uint8_t* val, ssize_t len)
    {
        // find the entry
        uint64_t offset = OFFSET(key[0], key[1], (key[2]>>4));

        // lock the bucket for writing
        std::unique_lock<std::shared_mutex> lock(mutexes[offset >> 18]);

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

    // out_len carries the length of the output buffer when calling and is replaced
    // with the length of the data found when returning
    int read_entry_internal(uint8_t* data, uint8_t* key, uint8_t* val_out, uint64_t* out_len)
    {
        // find the entry
        uint64_t offset = OFFSET(key[0], key[1], (key[2]>>4));
        uint8_t* start = data + offset;

        // lock the bucket for reading
        std::shared_lock<std::shared_mutex> lock(mutexes[offset >> 18]);

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

            if (size > *out_len)
                return 2;

            memcpy(val_out, start + i + 40, size);
            *out_len = size;

            return 0;
        }

        return 1;
    }
    
    void setup()
    {
        struct stat path_stat;

        if (stat(path.c_str(), &path_stat) != 0)
            throw std::runtime_error("Error checking path: " + path + " - " + std::string(strerror(errno)));

        if (!S_ISDIR(path_stat.st_mode))
            throw std::runtime_error("Path is not a directory: " + path);

        if (access(path.c_str(), R_OK | W_OK | X_OK) != 0)
            throw std::runtime_error("Insufficient permissions for path: " + path);

        // Search for existing snug files sequentially
        std::vector<std::string> snug_files;
        for (int file_index = 0; file_index < 1024; ++file_index)
        {
            std::string filename = "snug." + std::to_string(file_index);
            std::string full_path = path + "/" + filename;

            if (access(full_path.c_str(), F_OK) != 0)
                break;

            snug_files.push_back(filename);
        }

        // If no files found, create snug.0
        if (snug_files.empty())
        {
            std::string new_file = path + "/snug.0";
            int result = alloc_file(new_file.c_str());
            if (result != 0)
                throw std::runtime_error("Failed to create initial file: " + new_file);
            snug_files.push_back("snug.0");
        }

        // Memory map all files
        for (const auto& file : snug_files)
        {
            std::string full_path = path + "/" + file;
            if (check_file(full_path.c_str()) != 0)
                throw std::runtime_error("File was the wrong size: " + file);

            int fd = open(full_path.c_str(), O_RDWR);
            if (fd == -1)
                throw std::runtime_error("Unable to open file: " + full_path);

            struct stat file_stat;
            if (fstat(fd, &file_stat) == -1)
            {
                close(fd);
                throw std::runtime_error("Unable to get file stats: " + full_path);
            }

            void* mapped = mmap(nullptr, file_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            close(fd);  // Can close fd after mmap

            if (mapped == MAP_FAILED)
                throw std::runtime_error("Unable to mmap file: " + full_path);

            mapped_files[mapped_files_count++] = static_cast<uint8_t*>(mapped);
        }
    }
public:

    SnugDB(std::string path_) : path(path_)
    {
        setup();
    }

    ~SnugDB()
    {
        // Unmap all files in destructor
        // RH TODO: consider lock here
        for (int i = 0; i < mapped_files_count; ++i)
            munmap(mapped_files[i], SNUGSIZE);

    }

    int write_entry(uint8_t* key, uint8_t* val, ssize_t len)
    {
        for (size_t i = 0; i < mapped_files_count; ++i)
        {
            int result = write_entry_internal(mapped_files[i], key, val, len);
            if (result == 0)
                return 0;

            if (result != 1) // other error
                return result;
        }

        {
            // acquire the mutex
            const std::lock_guard<std::mutex> lock(mapped_files_count_mutex);

            // All existing files are full, allocate a new one
            std::string new_file = path + "/snug." + std::to_string(mapped_files_count);
            int alloc_result = alloc_file(new_file.c_str());
            if (alloc_result != 0)
                return alloc_result + 10;  // Return error code from alloc_file if it fails (+10)

            int fd = open(new_file.c_str(), O_RDWR);
            if (fd == -1)
                return 1;  // Return 1 for open failure

            struct stat file_stat;
            if (fstat(fd, &file_stat) == -1)
            {
                close(fd);
                return 2;  // Return 2 for fstat failure
            }

            void* mapped = mmap(nullptr, file_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            close(fd);  // Can close fd after mmap

            if (mapped == MAP_FAILED)
                return 3;  // Return 3 for mmap failure

            // add the new file to the map, and increment the counter
            mapped_files[mapped_files_count] = static_cast<uint8_t*>(mapped);

            // this is the last possible thing done
            mapped_files_count++;
        }

        // finally write the entry
        // RH TODO: consider adding a recursion guard here
        return write_entry(key, val, len);
    }

    int read_entry(uint8_t* key, uint8_t* val_out, uint64_t* out_len_ptr)
    {
        uint64_t out_len = *out_len_ptr;

        for (size_t i = 0; i < mapped_files_count; ++i)
        {
            int result = read_entry_internal(mapped_files[i], key, val_out, out_len_ptr);
            
            if (result == 0)
                return 0;  // Entry found and read successfully
            
            if (result == 2)
                return 2;  // Output buffer too small
            
            // If result is 1 (entry not found in this file), continue to the next file
            // Reset out_len for the next iteration
            *out_len_ptr = out_len;
        }
        
        // Entry not found in any file
        return 1;
    }

};


int main()
{
    uint8_t key[]{
            0xAB,0xAB,0xFF,0xAB,0xAB,0xAB,0xAB,0xAB,
            0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,
            0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,
            0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB};

    uint8_t val[] {0xDE, 0xAD, 0xBE, 0xEF, 0, 0};
    SnugDB db(".");
    /*
    for (int i = 0; i < 257; ++i)
    {
        key[2] = i >> 8;
        key[3] = i & 0xFF;
        val[4] = i >> 8;
        val[5] = i & 0xFF;

        db.write_entry(key, val, 6);
    }
    */


    for (int i = 0; i < 257; ++i)
    {
        key[2] = i >> 8;
        key[3] = i & 0xFF;
        uint8_t buf[1024];

        uint64_t len = 1024;

        printf("Read result: %d\n", db.read_entry(key, buf, &len));
        printf("Read len: %lu\n", len);
        printf("Buf: ");
        for (uint64_t i = 0; i < len; ++i)
            printf("%02X ", buf[i]);

        printf("\n");

    }
    return 0;
}
