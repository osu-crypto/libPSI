#pragma once
#include "Common/Defines.h"
#include "Crypto/AES.h"
#include "Crypto/sha1.h"
#include <vector>

#define SEED_SIZE   AES_BLK_SIZE
#define RAND_SIZE   AES_BLK_SIZE


namespace libPSI
{

	class PRNG
	{
	public:

		block mSeed;
		std::vector<block> mBuffer, mIndexArray;

		AES mAes;
		u64 mBytesIdx, mBlockIdx, mBufferByteCapacity;

		void refillBuffer();
		//block seed;
		//u8 state[SEED_SIZE];
		//u8 random[RAND_SIZE];


		//AES mKeyShedule;

		//u64 cnt;    // How many bytes of the current random value have been used

		//void hash(); // Hashes state to random and sets cnt=0
		//void next();


		PRNG();
		PRNG(const block& seed);
		PRNG(const PRNG&) = delete;
		
		// For debugging
		void print_state() const;

		// Set seed from dev/random
		//void ReSeed();

		// Set seed from array
		void SetSeed(const block& b);

		__m128i get_block();
		blockRIOT get_block512(u64 length);
		double get_double();
		u8 get_uchar();
		u32 get_u32();
		u8 get_bit() { return get_uchar() & 1; }
		//bigint randomBnd(const bigint& B);
		//modp get_modp(const Zp_Data& ZpD);
		u64 get_u64()
		{
			u64 a;
			get_u8s((u8*)&a, sizeof(a));
			return a;
		}
		//void get_ByteStream(ByteStream& ans, u64 len);
		void get_u8s(u8* ans, u64 len);

		const block get_seed() const
		{
			return mSeed;
		}


		typedef u64 result_type;
		static u64 min() { return 0; }
		static u64 max() { return (u64)-1; }
		u64 operator()() {
			return get_u64();
		}
		u64 operator()(u64 mod) {
			return get_u64() % mod;
		}
	};
}
