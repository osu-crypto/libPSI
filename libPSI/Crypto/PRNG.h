#pragma once
#include "Common/Defines.h"
#include "Crypto/AES.h"
#include "Crypto/sha1.h"
#include <vector>

#define SEED_SIZE   AES_BLK_SIZE
#define RAND_SIZE   AES_BLK_SIZE


namespace osuCrypto
{

	class PRNG
	{
	public:

		block mSeed;
		std::vector<block> mBuffer, mIndexArray;
		AES mAes;
		u64 mBytesIdx, mBlockIdx, mBufferByteCapacity;
		void refillBuffer();



		PRNG();
		PRNG(const block& seed);
		PRNG(const PRNG&) = delete;
		PRNG(PRNG&& s);


		// Set seed from array
		void SetSeed(const block& b);
		const block getSeed() const;


		template<typename T>
		T get()
		{
			static_assert(std::is_pod<T>::value, "T must be POD");
			T ret;
			get((u8*)&ret, sizeof(T));
			return ret;
		}


		u8 getBit() { return get<u8>() & 1; }
		void get(u8* ans, u64 len);




		typedef u64 result_type;
		static u64 min() { return 0; }
		static u64 max() { return (u64)-1; }
		u64 operator()() {
			return get<u64>();
		}
		u64 operator()(u64 mod) {
			return get<u64>() % mod;
		}
	};
}
