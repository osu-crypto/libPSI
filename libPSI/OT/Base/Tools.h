#pragma once
 
#include "Crypto/Commit.h"
#include "Crypto/PRNG.h"
#include "Common/Defines.h"
#include "Network/Channel.h"

#define SEED_SIZE_BYTES SEED_SIZE
namespace libPSI {
	/*
	 * Generate a secure, random seed between 2 parties via commitment
	 */
	void random_seed_commit(u8* seed, Channel& channel, int len, const block& prngSeed);

	/*
	 * GF(2^128) multiplication using Intel instructions
	 * (should this go in gf2n class???)
	 */
	void gfmul128(__m128i a, __m128i b, __m128i *res);
	// Without reduction
	void mul128(__m128i a, __m128i b, __m128i *res1, __m128i *res2);
	void gfred128(__m128i a1, __m128i a2, __m128i *res);

	//#endif
	void eklundh_transpose128(std::array<block, 128>& inOut);

	//std::string u64_to_bytes(const u64 w);

	//void shiftl128(u64 x1, u64 x2, u64& res1, u64& res2, size_t k);

}
