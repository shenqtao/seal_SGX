#pragma once

#include <cstdint>
#include "modulus.h"
#include "mempool.h"
#include "polymodulus.h"

namespace seal
{
    namespace util
    {
        void dyadic_product_coeffmod(const uint64_t *operand1, const uint64_t *operand2, int coeff_count, const Modulus &modulus, uint64_t *result, MemoryPool &pool);

        void modulo_poly_inplace(uint64_t *value, int value_coeff_count, const PolyModulus &poly_modulus, const Modulus &modulus, MemoryPool &pool);

        void modulo_poly(const uint64_t *value, int value_coeff_count, const PolyModulus &poly_modulus, const Modulus &modulus, uint64_t *result, MemoryPool &pool);

        void nonfft_multiply_poly_poly_polymod_coeffmod(const uint64_t *operand1, const uint64_t *operand2, const PolyModulus &poly_modulus, const Modulus &modulus, uint64_t *result, MemoryPool &pool);

        void nonfft_multiply_poly_poly_polymod_coeffmod_inplace(const uint64_t *operand1, const uint64_t *operand2, const PolyModulus &poly_modulus, const Modulus &modulus, uint64_t *result, MemoryPool &pool);

        // Not currently used
        bool try_invert_poly_coeffmod(const uint64_t *operand, const uint64_t *poly_modulus, int coeff_count, const Modulus &modulus, uint64_t *result, MemoryPool &pool);
    }
}