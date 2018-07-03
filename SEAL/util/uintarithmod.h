#pragma once

#include <cstdint>
#include "mempool.h"
#include "modulus.h"

namespace seal
{
    namespace util
    {
        void modulo_uint_inplace(uint64_t *value, int value_uint64_count, const Modulus &modulus, MemoryPool &pool, uint64_t *alloc_ptr = nullptr);

        void modulo_uint(const uint64_t *value, int value_uint64_count, const Modulus &modulus, uint64_t *result, MemoryPool &pool, uint64_t *alloc_ptr = nullptr);

        void increment_uint_mod(const uint64_t *operand, const uint64_t *modulus, int uint64_count, uint64_t *result);

        void decrement_uint_mod(const uint64_t *operand, const uint64_t *modulus, int uint64_count, uint64_t *result);

        void negate_uint_mod(const uint64_t *operand, const uint64_t *modulus, int uint64_count, uint64_t *result);

        void div2_uint_mod(const uint64_t *operand, const uint64_t *modulus, int uint64_count, uint64_t *result);

        void add_uint_uint_mod(const uint64_t *operand1, const uint64_t *operand2, const uint64_t *modulus, int uint64_count, uint64_t *result);

        void sub_uint_uint_mod(const uint64_t *operand1, const uint64_t *operand2, const uint64_t *modulus, int uint64_count, uint64_t *result);
        
        void multiply_uint_uint_mod(const uint64_t *operand1, const uint64_t *operand2, const Modulus &modulus, uint64_t *result, MemoryPool &pool, uint64_t *alloc_ptr = nullptr);

        void multiply_uint_uint_mod_inplace(const uint64_t *operand1, const uint64_t *operand2, const Modulus &modulus, uint64_t *result, MemoryPool &pool, uint64_t *alloc_ptr = nullptr);

        bool try_invert_uint_mod(const uint64_t *operand, const uint64_t *modulus, int uint64_count, uint64_t *result, MemoryPool &pool, uint64_t *alloc_ptr = nullptr);
    
        // Find if root is a primitive degree-th root of unity modulo prime_modulus, where degree must be a power of two.
        bool is_primitive_root(const uint64_t *root, uint64_t degree, const Modulus &prime_modulus, MemoryPool &pool);

        // Try to find a primitive degree-th root of unity modulo prime_modulus, where degree must be a power of two.
        bool try_primitive_root(uint64_t degree, const Modulus &prime_modulus, MemoryPool &pool, uint64_t *destination);

        // Try to find the smallest (as integer) primitive degree-th root of unity modulo prime_modulus, where degree must be a power of two.
        bool try_minimal_primitive_root(uint64_t degree, const Modulus &prime_modulus, MemoryPool &pool, uint64_t *destination);
    }
}