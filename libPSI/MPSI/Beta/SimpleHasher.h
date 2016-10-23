#pragma once
#include "Common/Defines.h"
#include "Common/BitVector.h"
#include "Common/ArrayView.h"

namespace osuCrypto
{
	//// a list of {{set size, bit size}}
	//std::vector<std::array<u64, 2>> binSizes
	//{
	//	{1<<12, 18},
	//	{1<<16, 19},
	//	{1<<20, 20},
	//	{1<<24, 21}
	//};


	class SimpleHasher
	{
	public:
		SimpleHasher();
		~SimpleHasher();

		typedef std::vector<u64> Bin;
		//typedef std::vector<std::pair<u64, block>> Bin;

		u64 mBinCount , mMaxBinSize, mRepSize, mInputBitSize, mN;

		std::unique_ptr<std::mutex[]> mMtx;
		std::vector<Bin> mBins;
		block mHashSeed;

		void print() const;

		void init(u64 n, u64 numBits, block hashSeed, u64 secParam);

		//void preHashedInsertItems(ArrayView<block> items, u64 itemIdx);
		//void insertItemsWithPhasing(ArrayView<block> items, u64 itemIdx);
	};

}
