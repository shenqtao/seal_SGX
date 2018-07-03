#pragma once

#include <cstdint>
#include "mempool.h"
#include "modulus.h"

namespace seal
{
    namespace util
    {
        void exponentiate_uint(const uint64_t *operand, int operand_uint64_count, const uint64_t *exponent,
            int exponent_uint64_count, int result_uint64_count, uint64_t *result, MemoryPool &pool);

        void exponentiate_uint_mod(const uint64_t *operand, const uint64_t *exponent, int exponent_uint64_count, 
            const util::Modulus &modulus, uint64_t *result, MemoryPool &pool);
    }
}