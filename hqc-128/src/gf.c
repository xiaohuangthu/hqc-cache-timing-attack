/**
 * @file gf.c
 * @brief Galois field implementation with multiplication using lookup tables
 */

#include "gf.h"
#include "parameters.h"
#include <stdint.h>


/**
 * Generates gf_exp and gf_log lookup tables of GF(2^m).
 * The logarithm of 0 is defined as 0 by convention. <br>
 * The last two elements of the gf_exp table are needed by the gf_mul function.
 * (for example if both elements to multiply are zero).
 * @param[out] exp Array of size 2^PARAM_M + 2 receiving the powers of the primitive element
 * @param[out] log Array of size 2^PARAM_M receiving the logarithms of the elements of GF(2^m)
 * @param[in] m Parameter of Galois field GF(2^m)
 */
void gf_generate(uint16_t *exp, uint16_t *log, const int16_t m) {
    uint16_t elt = 1;
    uint16_t alpha = 2; // primitive element of GF(2^PARAM_M)
    uint16_t gf_poly = PARAM_GF_POLY;

    for (size_t i = 0 ; i < (1U << m) - 1 ; ++i) {
        exp[i] = elt;
        log[elt] = i;

        elt *= alpha;
        if (elt >= 1 << m) {
            elt ^= gf_poly;
        }
    }

    exp[(1 << m) - 1] = 1;
    exp[1 << m] = 2;
    exp[(1 << m) + 1] = 4;
    log[0] = 0; // by convention
}



/**
 * Multiplies nonzero element 'a' by element 'b'.
 * @returns the product a*b
 * @param[in] a First element of GF(2^PARAM_M) to multiply (cannot be zero)
 * @param[in] b Second element of GF(2^PARAM_M) to multiply (cannot be zero)
 */
uint16_t gf_mul(uint16_t a, uint16_t b) {
    uint16_t mask;
    mask = (uint16_t) (-((int32_t) a) >> 31); // a != 0
    mask &= (uint16_t) (-((int32_t) b) >> 31); // b != 0
    return mask & gf_exp[gf_mod(gf_log[a] + gf_log[b])];
}



/**
 * Squares an element of GF(2^PARAM_M).
 * @returns a^2
 * @param[in] a Element of GF(2^PARAM_M)
 */
uint16_t gf_square(uint16_t a) {
    int16_t mask = (uint16_t) (-((int32_t) a) >> 31); // a != 0
    return mask & gf_exp[gf_mod(2 * gf_log[a])];
}



/**
 * Computes the inverse of an element of GF(2^PARAM_M).
 * @returns the inverse of a
 * @param[in] a Element of GF(2^PARAM_M)
 */
uint16_t gf_inverse(uint16_t a) {
    int16_t mask = (uint16_t) (-((int32_t) a) >> 31); // a != 0
    return mask & gf_exp[PARAM_GF_MUL_ORDER - gf_log[a]];
}



/**
 * Returns i modulo 2^PARAM_M-1.
 * i must be less than 2*(2^PARAM_M-1).
 * Therefore, the return value is either i or i-2^PARAM_M+1.
 * @returns i mod (2^PARAM_M-1)
 * @param[in] i The integer whose modulo is taken
 */
uint16_t gf_mod(uint16_t i) {
    uint16_t tmp = i - PARAM_GF_MUL_ORDER;

    // mask = 0xffff if(i < PARAM_GF_MUL_ORDER)
    int16_t mask = -(tmp >> 15);

    return tmp + (mask & PARAM_GF_MUL_ORDER);
}
