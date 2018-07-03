#pragma once

#include <cstdint>
#include "polycore.h"
#include "mempool.h"
#include "uintarithmod.h"

namespace seal
{
    namespace util
    {
        void modulo_poly_coeffs(uint64_t *poly, int coeff_count, const Modulus &modulus, MemoryPool &pool);

        void negate_poly(const uint64_t *poly, int coeff_count, int coeff_uint64_count, uint64_t *result);

        void negate_poly_coeffmod(const uint64_t *poly, int coeff_count, const uint64_t *coeff_modulus, int coeff_uint64_count, uint64_t *result);

        void add_poly_poly(const uint64_t *operand1, const uint64_t *operand2, int coeff_count, int coeff_uint64_count, uint64_t *result);

        void sub_poly_poly(const uint64_t *operand1, const uint64_t *operand2, int coeff_count, int coeff_uint64_count, uint64_t *result);

        void add_poly_poly_coeffmod(const uint64_t *operand1, const uint64_t *operand2, int coeff_count, const uint64_t *coeff_modulus, int coeff_uint64_count, uint64_t *result);

        void sub_poly_poly_coeffmod(const uint64_t *operand1, const uint64_t *operand2, int coeff_count, const uint64_t *coeff_modulus, int coeff_uint64_count, uint64_t *result);

        void multiply_poly_scalar_coeffmod(const uint64_t *poly, int coeff_count, const uint64_t *scalar, const Modulus &modulus, uint64_t *result, MemoryPool &pool);

        void multiply_poly_poly(const uint64_t *operand1, int operand1_coeff_count, int operand1_coeff_uint64_count, const uint64_t *operand2, int operand2_coeff_count, int operand2_coeff_uint64_count,
            int result_coeff_count, int result_coeff_uint64_count, uint64_t *result, MemoryPool &pool);

        void multiply_poly_poly_coeffmod(const uint64_t *operand1, int operand1_coeff_count, int operand1_coeff_uint64_count, const uint64_t *operand2, int operand2_coeff_count, int operand2_coeff_uint64_count,
            const Modulus &modulus, int result_coeff_count, uint64_t *result, MemoryPool &pool);

        inline void multiply_poly_poly_coeffmod(const uint64_t *operand1, const uint64_t *operand2, int coeff_count, const Modulus &modulus, uint64_t *result, MemoryPool &pool)
        {
            int result_coeff_count = coeff_count + coeff_count - 1;
            int coeff_uint64_count = modulus.uint64_count();
            multiply_poly_poly_coeffmod(operand1, coeff_count, coeff_uint64_count, operand2, coeff_count, coeff_uint64_count, modulus, result_coeff_count, result, pool);
        }

        inline void multiply_truncate_poly_poly_coeffmod(const uint64_t *operand1, const uint64_t *operand2, int coeff_count, const Modulus &modulus, uint64_t *result, MemoryPool &pool)
        {
            int coeff_uint64_count = modulus.uint64_count();
            multiply_poly_poly_coeffmod(operand1, coeff_count, coeff_uint64_count, operand2, coeff_count, coeff_uint64_count, modulus, coeff_count, result, pool);
        }

        void divide_poly_poly_coeffmod_inplace(uint64_t *numerator, const uint64_t *denominator, int coeff_count, const Modulus &modulus, uint64_t *quotient, MemoryPool &pool);

        inline void divide_poly_poly_coeffmod(const uint64_t *numerator, const uint64_t *denominator, int coeff_count, const Modulus &modulus, uint64_t *quotient, uint64_t *remainder, MemoryPool &pool)
        {
            int coeff_uint64_count = modulus.uint64_count();
            set_poly_poly(numerator, coeff_count, coeff_uint64_count, remainder);
            divide_poly_poly_coeffmod_inplace(remainder, denominator, coeff_count, modulus, quotient, pool);
        }

        void add_bigpolyarray_coeffmod(const uint64_t *array1, const uint64_t *array2, int count, int coeff_count, const Modulus &modulus, uint64_t *result);
    }
}