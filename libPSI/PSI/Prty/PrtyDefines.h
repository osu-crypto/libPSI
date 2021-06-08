#pragma once
#include "libPSI/config.h"
#ifdef ENABLE_PRTY_PSI

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Log.h>
#define NTL_Threads
#define  DEBUG
#include "PrtyDefines.h"
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ.h>
//using namespace NTL;
#define NTL_Threads_ON



namespace osuCrypto
{
	using ZZ =NTL::ZZ;

	static const u64 stepSize(1 << 2);
	static const u64 stepSizeMaskSent(1 << 14);
	static const u8 numSuperBlocks(4); //wide of T (or field size)
	static const u8 first2Slices(2); //2*128 + (436-2*128)
	static const u64 recvNumDummies(1);
	static const u64 recvMaxBinSize(40);
	static std::vector<block> mOneBlocks(128);
	static const u64 primeLong(129);
	static const u64 fieldSize(440); //TODO 4*sizeof(block)

	static const u64 bIdxForDebug(3), iIdxForDebug(0), hIdxForDebug(0);

	static const ZZ mPrime128 = NTL::to_ZZ("340282366920938463463374607431768211507");
	static const ZZ mPrime160 = NTL::to_ZZ("1461501637330902918203684832716283019655932542983");  //nextprime(2^160)
	static const ZZ mPrime164 = NTL::to_ZZ("23384026197294446691258957323460528314494920687733");  //nextprime(2^164)
	static const ZZ mPrime168 = NTL::to_ZZ("374144419156711147060143317175368453031918731001943");  //nextprime(2^168)
	static const ZZ mPrime172 = NTL::to_ZZ("5986310706507378352962293074805895248510699696029801");  //nextprime(2^172)
	static const ZZ mPrime176 = NTL::to_ZZ("95780971304118053647396689196894323976171195136475563");  //nextprime(2^176)
	static const ZZ mPrime180 = NTL::to_ZZ("1532495540865888858358347027150309183618739122183602191");  //nextprime(2^180)
	static const ZZ mPrime184 = NTL::to_ZZ("24519928653854221733733552434404946937899825954937634843");  //nextprime(2^184)
	static const ZZ mPrime188 = NTL::to_ZZ("392318858461667547739736838950479151006397215279002157113");  //nextprime(2^188)

	inline u64 getFieldSizeInBits(u64 setSize)
	{

		if (setSize <= (1 << 10))
			return 416;
		else if (setSize <= (1 << 12))
			return 420;
		else if (setSize <= (1 << 14))
			return 424;
		else if (setSize <= (1 << 16))
			return 428;
		else if (setSize <= (1 << 18))
			return 432;
		else if (setSize <= (1 << 20))
			return 436;
		else if (setSize <= (1 << 22))
			return 436;
		else if (setSize <= (1 << 24))
			return 444;

		return 444;
	}


	inline ZZ getPrimeLastSlice(u64 fieldSize)
	{
		u64 lastBit = fieldSize - 2 * 128;
		if (lastBit == 160)
			return mPrime160;
		else if (lastBit == 164)
			return mPrime164;
		else if (lastBit == 168)
			return mPrime168;
		else if (lastBit == 172)
			return mPrime172;
		else if (lastBit == 176)
			return mPrime176;
		else if (lastBit == 180)
			return mPrime180;
		else if (lastBit == 184)
			return mPrime184;
		else if (lastBit == 188)
			return mPrime188;

		return mPrime188;
	}



	inline __m128i mm_bitshift_right(__m128i x, unsigned count)
	{
		__m128i carry = _mm_slli_si128(x, 8);   // old compilers only have the confusingly named _mm_slli_si128 synonym
		if (count >= 64)
			return _mm_slli_epi64(carry, count - 64);  // the non-carry part is all zero, so return early
													   // else
		return _mm_or_si128(_mm_slli_epi64(x, count), _mm_srli_epi64(carry, 64 - count));

	}


	inline __m128i mm_bitshift_left(__m128i x, unsigned count)
	{
		__m128i carry = _mm_srli_si128(x, 8);   // old compilers only have the confusingly named _mm_slli_si128 synonym
		if (count >= 64)
			return _mm_srli_epi64(carry, count - 64);  // the non-carry part is all zero, so return early

		return _mm_or_si128(_mm_srli_epi64(x, count), _mm_slli_epi64(carry, 64 - count));
	}

	inline void fillOneBlock(std::vector<block>& blks)
	{
		for (int i = 0; i < blks.size(); ++i)
			blks[i] = mm_bitshift_right(OneBlock, i);
	}

	inline void prfOtRows(span<block> inputs, std::vector<std::array<block, numSuperBlocks>>& outputs, std::vector<AES>& arrAes)
	{
		std::vector<block> ciphers(inputs.size());
		outputs.resize(inputs.size());

		for (int j = 0; j < numSuperBlocks - 1; ++j) //1st 3 blocks
			for (int i = 0; i < 128; ++i) //for each column
			{
				arrAes[j * 128 + i].ecbEncBlocks(inputs.data(), inputs.size(), ciphers.data()); //do many aes at the same time for efficeincy

				for (u64 idx = 0; idx < inputs.size(); idx++)
				{
					ciphers[idx] = ciphers[idx] & mOneBlocks[i];
					outputs[idx][j] = outputs[idx][j] ^ ciphers[idx];
				}
			}


		int j = numSuperBlocks - 1;
		for (int i = j * 128; i < arrAes.size(); ++i)
		{
			arrAes[i].ecbEncBlocks(inputs.data(), inputs.size(), ciphers.data()); //do many aes at the same time for efficeincy
			for (u64 idx = 0; idx < inputs.size(); idx++)
			{
				ciphers[idx] = ciphers[idx] & mOneBlocks[i - j * 128];
				outputs[idx][j] = outputs[idx][j] ^ ciphers[idx];
			}

		}

	}

	inline void prfOtRow(block& input, std::array<block, numSuperBlocks>& output, std::vector<AES> arrAes, u64 hIdx = 0)
	{
		block cipher;

		for (int j = 0; j < numSuperBlocks - 1; ++j) //1st 3 blocks
			for (int i = 0; i < 128; ++i) //for each column
			{
				if (hIdx == 1)
					arrAes[j * 128 + i].ecbEncBlock(input ^ OneBlock, cipher);
				else
					arrAes[j * 128 + i].ecbEncBlock(input, cipher);

				cipher = cipher & mOneBlocks[i];
				output[j] = output[j] ^ cipher;
			}


		int j = numSuperBlocks - 1;
		for (int i = 0; i < 128; ++i)
		{
			if (j * 128 + i < arrAes.size()) {

				if (hIdx == 1)
					arrAes[j * 128 + i].ecbEncBlock(input ^ OneBlock, cipher);
				else
					arrAes[j * 128 + i].ecbEncBlock(input, cipher);

				cipher = cipher & mOneBlocks[i];
				output[j] = output[j] ^ cipher;
			}
			else {
				break;
			}
		}

		//std::cout << IoStream::lock;
		//std::cout << "\t output " << output[0] << "\n";
		//std::cout << IoStream::unlock;

	}

}
#endif