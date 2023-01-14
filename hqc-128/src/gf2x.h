#ifndef GF2X_H
#define GF2X_H

/**
 * @file gf2x.h
 * @brief Header file for gf2x.c
 */

#include "shake_prng.h"
#include <stdint.h>

void vect_mul(uint64_t *o, const uint32_t *v1, const uint64_t *v2, const uint16_t weight, seedexpander_state *ctx);

#endif
