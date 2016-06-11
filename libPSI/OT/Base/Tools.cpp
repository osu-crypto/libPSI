#include "Tools.h"
#include "Common/Defines.h"
#include "Crypto/PRNG.h"
#include "Common/Log.h"
#include <wmmintrin.h>

#ifndef _MSC_VER
#include <x86intrin.h>
#endif 

namespace libPSI {

	void random_seed_commit(u8* seed, Channel& channel, int len, const block& prngSeed)
	{
		PRNG G;
		//G.ReSeed();
		G.SetSeed(prngSeed);

		//ByteStream mySeed, myComm, myOpen;
		//ByteStream theirSeed, theirComm, theirOpen;

		block mySeed, myMask, theirSeed, theirMask;

		mySeed = G.get_block();
		myMask = G.get_block();

		//G.get_ByteStream(mySeed, len);
		Commit myComm(mySeed, myMask);
		Commit theirCommit;
		//CommitComm(myComm, myOpen, mySeed, G);

		channel.send(myComm.data(), myComm.size());
		channel.recv(theirCommit.data(), theirCommit.size());

		channel.send((u8*)&mySeed, sizeof(block));
		channel.send((u8*)&myMask, sizeof(block));
		channel.recv((u8*)&theirSeed, sizeof(block));
		channel.recv((u8*)&theirMask, sizeof(block));

		if (Commit(theirSeed, theirMask) != theirCommit)
		{
			Log::out << "commitment Open failed" << Log::endl;
			throw invalid_commitment();
		}

		PRNG gen(mySeed ^ theirSeed);
		gen.get_u8s(seed, len);

		//Log::out << "Their str  " <<  theirSeed  << Log::endl;
		//for (int i = 0; i < len; i++)
		//{
		//	seed[i] = mySeed.data()[i] ^ theirSeed.data()[i];
		//}
	}
	
	//void shiftl128(u64 x1, u64 x2, u64& res1, u64& res2, size_t k)
	//{
	//   if (k > 128)
	//      throw invalid_length();
	//   if (k >= 64) // shifting a 64-bit integer by more than 63 bits is "undefined"
	//   {
	//      x1 = x2;
	//      x2 = 0;
	//      shiftl128(x1, x2, res1, res2, k - 64);
	//   }
	//   else
	//   {
	//      res1 = (x1 << k) | (x2 >> (64 - k));
	//      res2 = (x2 << k);
	//   }
	//}

	void mul128(__m128i a, __m128i b, __m128i *res1, __m128i *res2)
	{
		__m128i tmp3, tmp4, tmp5, tmp6;

		tmp3 = _mm_clmulepi64_si128(a, b, (int)0x00);
		tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
		tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
		tmp6 = _mm_clmulepi64_si128(a, b, 0x11);

		tmp4 = _mm_xor_si128(tmp4, tmp5);
		tmp5 = _mm_slli_si128(tmp4, 8);
		tmp4 = _mm_srli_si128(tmp4, 8);
		tmp3 = _mm_xor_si128(tmp3, tmp5);
		tmp6 = _mm_xor_si128(tmp6, tmp4);
		// initial mul now in tmp3, tmp6
		*res1 = tmp3;
		*res2 = tmp6;
	}

	// reduce modulo x^128 + x^7 + x^2 + x + 1
	// NB this is incorrect as it bit-reflects the result as required for
	// GCM mode
	void gfred128(__m128i tmp3, __m128i tmp6, __m128i *res)
	{
		__m128i tmp2, tmp4, tmp5, tmp7, tmp8, tmp9;
		tmp7 = _mm_srli_epi32(tmp3, 31);
		tmp8 = _mm_srli_epi32(tmp6, 31);

		tmp3 = _mm_slli_epi32(tmp3, 1);
		tmp6 = _mm_slli_epi32(tmp6, 1);

		tmp9 = _mm_srli_si128(tmp7, 12);
		tmp8 = _mm_slli_si128(tmp8, 4);
		tmp7 = _mm_slli_si128(tmp7, 4);
		tmp3 = _mm_or_si128(tmp3, tmp7);
		tmp6 = _mm_or_si128(tmp6, tmp8);
		tmp6 = _mm_or_si128(tmp6, tmp9);

		tmp7 = _mm_slli_epi32(tmp3, 31);
		tmp8 = _mm_slli_epi32(tmp3, 30);
		tmp9 = _mm_slli_epi32(tmp3, 25);

		tmp7 = _mm_xor_si128(tmp7, tmp8);
		tmp7 = _mm_xor_si128(tmp7, tmp9);
		tmp8 = _mm_srli_si128(tmp7, 4);
		tmp7 = _mm_slli_si128(tmp7, 12);
		tmp3 = _mm_xor_si128(tmp3, tmp7);

		tmp2 = _mm_srli_epi32(tmp3, 1);
		tmp4 = _mm_srli_epi32(tmp3, 2);
		tmp5 = _mm_srli_epi32(tmp3, 7);
		tmp2 = _mm_xor_si128(tmp2, tmp4);
		tmp2 = _mm_xor_si128(tmp2, tmp5);
		tmp2 = _mm_xor_si128(tmp2, tmp8);
		tmp3 = _mm_xor_si128(tmp3, tmp2);

		tmp6 = _mm_xor_si128(tmp6, tmp3);
		*res = tmp6;
	}

	// Based on Intel's code for GF(2^128) mul, with reduction
	void gfmul128(__m128i a, __m128i b, __m128i *res)
	{
		__m128i tmp3, tmp6;
		mul128(a, b, &tmp3, &tmp6);
		// Now do the reduction
		gfred128(tmp3, tmp6, res);
	}

	//std::string u64_to_bytes(const u64 w)
	//{
	//	std::stringstream ss;
	//	u8* bytes = (u8*)&w;
	//	ss << std::hex;
	//	for (unsigned int i = 0; i < sizeof(u64); i++)
	//		ss << (int)bytes[i] << " ";
	//	return ss.str();
	//}

	//void transpose512(void* data)
	//{
	//	for (...)
	//	{
	//		for (...)
	//		{
	//			eklundh_transpose128

	//			move...
	//		}
	//	}
	//}


	void eklundh_transpose128(std::array<block, 128>& inOut)
	{
		const static u64 TRANSPOSE_MASKS128[7][2] = {
			{ 0x0000000000000000, 0xFFFFFFFFFFFFFFFF },
			{ 0x00000000FFFFFFFF, 0x00000000FFFFFFFF },
			{ 0x0000FFFF0000FFFF, 0x0000FFFF0000FFFF },
			{ 0x00FF00FF00FF00FF, 0x00FF00FF00FF00FF },
			{ 0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F },
			{ 0x3333333333333333, 0x3333333333333333 },
			{ 0x5555555555555555, 0x5555555555555555 }
		};

		u32 width = 64;
		u32 logn = 7, nswaps = 1;

#ifdef TRANSPOSE_DEBUG
		stringstream input_ss[128];
		stringstream output_ss[128];
#endif

		// now transpose output in-place
		for (u32 i = 0; i < logn; i++)
		{
			u64 mask1 = TRANSPOSE_MASKS128[i][1], mask2 = TRANSPOSE_MASKS128[i][0];
			u64 inv_mask1 = ~mask1, inv_mask2 = ~mask2;

			// for width >= 64, shift is undefined so treat as a special case
			// (and avoid branching in inner loop)
			if (width < 64)
			{
				for (u32 j = 0; j < nswaps; j++)
				{
					for (u32 k = 0; k < width; k++)
					{
						u32 i1 = k + 2 * width*j;
						u32 i2 = k + width + 2 * width*j;

						// t1 is lower 64 bits, t2 is upper 64 bits
						// (remember we're transposing in little-endian format)
						u64& d1 = ((u64*)&inOut[i1])[0];
						u64& d2 = ((u64*)&inOut[i1])[1];

						u64& dd1 = ((u64*)&inOut[i2])[0];
						u64& dd2 = ((u64*)&inOut[i2])[1];

						u64 t1 = d1;
						u64 t2 = d2;

						u64 tt1 = dd1;
						u64 tt2 = dd2;

						// swap operations due to little endian-ness
						d1 = (t1 & mask1) ^ ((tt1 & mask1) << width);

						d2 = (t2 & mask2) ^
							((tt2 & mask2) << width) ^
							((tt1 & mask1) >> (64 - width));

						dd1 = (tt1 & inv_mask1) ^
							((t1 & inv_mask1) >> width) ^
							((t2 & inv_mask2)) << (64 - width);

						dd2 = (tt2 & inv_mask2) ^
							((t2 & inv_mask2) >> width);
					}
				}
			}
			else
			{
				for (u32 j = 0; j < nswaps; j++)
				{
					for (u32 k = 0; k < width; k++)
					{
						u32 i1 = k + 2 * width*j;
						u32 i2 = k + width + 2 * width*j;

						// t1 is lower 64 bits, t2 is upper 64 bits
						// (remember we're transposing in little-endian format)
						u64& d1 = ((u64*)&inOut[i1])[0];
						u64& d2 = ((u64*)&inOut[i1])[1];

						u64& dd1 = ((u64*)&inOut[i2])[0];
						u64& dd2 = ((u64*)&inOut[i2])[1];

						//u64 t1 = d1;
						u64 t2 = d2;

						//u64 tt1 = dd1;
						//u64 tt2 = dd2;

						d1 &= mask1;
						d2 = (t2 & mask2) ^
							((dd1 & mask1) >> (64 - width));

						dd1 = (dd1 & inv_mask1) ^
							((t2 & inv_mask2)) << (64 - width);

						dd2 &= inv_mask2;
					}
				}
			}
			nswaps *= 2;
			width /= 2;
		}
#ifdef TRANSPOSE_DEBUG
		for (u32 colIdx = 0; colIdx < 128; colIdx++)
		{
			for (u32 blkIdx = 0; blkIdx < 128; blkIdx++)
			{
				output_ss[blkIdx] << inOut[offset + blkIdx].get_bit(colIdx);
			}
		}
		for (u32 colIdx = 0; colIdx < 128; colIdx++)
		{
			if (output_ss[colIdx].str().compare(input_ss[colIdx].str()) != 0)
			{
				cerr << "String " << colIdx << " failed. offset = " << offset << endl;
				exit(1);
			}
		}
		cout << "\ttranspose with offset " << offset << " ok\n";
#endif
	}
}
