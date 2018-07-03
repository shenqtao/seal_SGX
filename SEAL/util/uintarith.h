#pragma once

#include <stdexcept>
#include <cstdint>
#include <functional>
#include "uintcore.h"
#include "mempool.h"
#include "modulus.h"
#include "defines.h"

#include <iostream>
namespace seal
{
    namespace util
    {
        unsigned char increment_uint(const uint64_t *operand, int uint64_count, uint64_t *result);

        unsigned char decrement_uint(const uint64_t *operand, int uint64_count, uint64_t *result);

        void negate_uint(const uint64_t *operand, int uint64_count, uint64_t *result);

        void left_shift_uint(const uint64_t *operand, int shift_amount, int uint64_count, uint64_t *result);

        void right_shift_uint(const uint64_t *operand, int shift_amount, int uint64_count, uint64_t *result);

        void right_shift_sign_extend_uint(const uint64_t *operand, int shift_amount, int uint64_count, uint64_t *result);

        void half_round_up_uint(const uint64_t *operand, int uint64_count, uint64_t *result);

        void not_uint(const uint64_t *operand, int uint64_count, uint64_t *result);

        void and_uint_uint(const uint64_t *operand1, const uint64_t *operand2, int uint64_count, uint64_t *result);

        void or_uint_uint(const uint64_t *operand1, const uint64_t *operand2, int uint64_count, uint64_t *result);

        void xor_uint_uint(const uint64_t *operand1, const uint64_t *operand2, int uint64_count, uint64_t *result);

        inline unsigned char add_uint64_uint64_generic(uint64_t operand1, uint64_t operand2, unsigned char carry, uint64_t *result)
        {
#ifdef _DEBUG
            if (result == nullptr)
            {
                throw std::invalid_argument("result cannot be null");
            }
#endif
            operand1 += operand2;
            *result = operand1 + carry;
            return (operand1 < operand2) || (~operand1 < carry);

            //// Same as
            //uint64_t sum = operand1 + operand2;
            //*result = sum + carry;
            //return (~sum < carry) | (sum < operand1);
        }

        inline unsigned char add_uint64_uint64(uint64_t operand1, uint64_t operand2, unsigned char carry, uint64_t *result)
        {
            return ADD_CARRY_UINT64(operand1, operand2, carry, result);
        }

        unsigned char add_uint_uint(const uint64_t *operand1, int operand1_uint64_count, const uint64_t *operand2, int operand2_uint64_count, unsigned char carry, int result_uint64_count, uint64_t *result);

        unsigned char add_uint_uint(const uint64_t *operand1, const uint64_t *operand2, int uint64_count, uint64_t *result);

        inline unsigned char sub_uint64_uint64_generic(uint64_t operand1, uint64_t operand2, unsigned char borrow, uint64_t *result)
        {
#ifdef _DEBUG
            if (result == nullptr)
            {
                throw std::invalid_argument("result cannot be null");
            }
#endif
            uint64_t diff = operand1 - operand2;
            *result = diff - (borrow != 0);
            return (diff > operand1) || (diff < borrow);
        }

        inline unsigned char sub_uint64_uint64(uint64_t operand1, uint64_t operand2, unsigned char borrow, uint64_t *result)
        {
            return SUB_BORROW_UINT64(operand1, operand2, borrow, result);
        }

        unsigned char sub_uint_uint(const uint64_t *operand1, int operand1_uint64_count, const uint64_t *operand2, int operand2_uint64_count, unsigned char borrow, int result_uint64_count, uint64_t *result);

        unsigned char sub_uint_uint(const uint64_t *operand1, const uint64_t *operand2, int uint64_count, uint64_t *result);

        inline uint64_t multiply_uint64_uint64_generic(uint64_t operand1, uint64_t operand2, uint64_t *carry)
        {
#ifdef _DEBUG
            if (carry == nullptr)
            {
                throw std::invalid_argument("carry cannot be null");
            }
#endif
            uint64_t operand1_coeff_right = operand1 & 0x00000000FFFFFFFF;
            uint64_t operand2_coeff_right = operand2 & 0x00000000FFFFFFFF;
            operand1 >>= 32;
            operand2 >>= 32;

            uint64_t middle1 = operand1 * operand2_coeff_right;
            uint64_t middle;
            uint64_t left = operand1 * operand2
                + (static_cast<uint64_t>(add_uint64_uint64(middle1, operand2 * operand1_coeff_right, 0, &middle)) << 32);
            uint64_t right = operand1_coeff_right * operand2_coeff_right;

            uint64_t temp_sum = (right >> 32) + (middle & 0x00000000FFFFFFFF);
            *carry = left + (middle >> 32) + (temp_sum >> 32);

            return (temp_sum << 32) | (right & 0x00000000FFFFFFFF);
        }

        inline uint64_t multiply_uint64_uint64(const uint64_t &operand1, const uint64_t &operand2, uint64_t *carry)
        {
            return MULTIPLY_UINT64(operand1, operand2, carry);
        }

        void multiply_uint_uint(const uint64_t *operand1, int operand1_uint64_count, const uint64_t *operand2, int operand2_uint64_count, int result_uint64_count, uint64_t *result);

        inline void multiply_uint_uint(const uint64_t *operand1, const uint64_t *operand2, int uint64_count, uint64_t *result)
        {
            multiply_uint_uint(operand1, uint64_count, operand2, uint64_count, uint64_count * 2, result);
        }

        void multiply_uint_uint64(const uint64_t *operand1, int operand1_uint64_count, uint64_t operand2, int result_uint64_count, uint64_t *result);

        inline void multiply_truncate_uint_uint(const uint64_t *operand1, const uint64_t *operand2, int uint64_count, uint64_t *result)
        {
            multiply_uint_uint(operand1, uint64_count, operand2, uint64_count, uint64_count, result);
        }

        void divide_uint_uint_inplace(uint64_t *numerator, const uint64_t *denominator, int uint64_count, uint64_t *quotient, MemoryPool &pool, uint64_t *alloc_ptr = nullptr);

        void divide_uint_uint_inplace(uint64_t *numerator, const Modulus &denominator, int uint64_count, uint64_t *quotient, MemoryPool &pool, uint64_t *alloc_ptr = nullptr);

        inline void divide_uint_uint(const uint64_t *numerator, const uint64_t *denominator, int uint64_count, uint64_t *quotient, uint64_t *remainder, MemoryPool &pool, uint64_t *alloc_ptr = nullptr)
        {
            // alloc_ptr should point to 2 x uint64_count memory

            set_uint_uint(numerator, uint64_count, remainder);
            divide_uint_uint_inplace(remainder, denominator, uint64_count, quotient, pool, alloc_ptr);
        }
    }
}
