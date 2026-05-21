#ifndef __PLATFORM_LIB_LINUX_MMAP_LINUX_H__
#define __PLATFORM_LIB_LINUX_MMAP_LINUX_H__

#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <exception>
#include <system_error>

class mmap_allocator {
    public:
        explicit mmap_allocator(uint32_t size) :
                                    mem_(nullptr),
                                    offset_(0),
                                    size_(size),
                                    page_size_(sysconf(_SC_PAGESIZE))
        {
            uint32_t perms = PROT_READ | PROT_WRITE;
            uint32_t map_options = MAP_PRIVATE | MAP_ANONYMOUS;
            uint32_t map_hugetlb = map_options | MAP_HUGETLB;

            /* Allocate huge pages first. */
            this->mem_ = mmap(nullptr,
                              this->size_,
                              perms,
                              map_hugetlb,
                              -1,
                              0);
            if (this->mem_ == MAP_FAILED) {
                /* Retry for normal pages. */
                this->mem_ = mmap(nullptr,
                                  this->size_,
                                  perms,
                                  map_options | MAP_POPULATE,
                                  -1,
                                  0);
                if (this->mem_ == MAP_FAILED) {
                    std::system_error(errno, std::generic_category(), "mmap failed");
                }
            }
        }

        ~mmap_allocator()
        {
            if (this->mem_) {
                munmap(this->mem_, this->size_);
            }
        }

        void *allocate(uint32_t size)
        {
            size = (size + this->page_size_ - 1) & ~(this->page_size_ - 1);
            if (size > (this->size_ - this->offset_)) {
                return nullptr;
            }

            void *ptr = (uint8_t *)this->mem_ + this->offset_;
            this->offset_ += size;

            return ptr;
        }

    private:
        void *mem_;
        uint32_t offset_;
        uint32_t size_;
        uint32_t page_size_;
};

#endif
