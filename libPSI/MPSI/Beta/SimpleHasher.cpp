#include "SimpleHasher.h"
#include "Crypto/sha1.h"
#include "Crypto/PRNG.h"
#include <random>
#include "Common/Log.h"
#include <numeric>

namespace osuCrypto
{


	SimpleHasher::SimpleHasher()
	{
	}


	SimpleHasher::~SimpleHasher()
	{
	}

	void SimpleHasher::print() const
	{

		//Log::out << Log::lock;
		for (u64 i = 0; i < mBins.size(); ++i)
		{
			Log::out << "Bin #" << i << Log::endl;

			Log::out << " contains " << mBins[i].size() << " elements" << Log::endl;

			for (u64 j = 0; j < mBins[i].size(); ++j)
			{
				Log::out
					<< "    " << mBins[i][j]  
					/*<< "  " << mBins[i][j].second */<< Log::endl;
			}

			Log::out << Log::endl; 
		}

		Log::out << Log::endl;// << Log::unlock;
	}

	double maxprob(u64 balls, u64 bins, u64 k)
	{
		return std::log(bins * std::pow(balls * exp(1) / (bins * k), k)) / std::log(2);
	}

	void SimpleHasher::init(u64 n, u64 numBits, block hashSeed, u64 secParam)
	{
		mHashSeed = hashSeed;
		mN = n;

		auto log2n = log2ceil(n);

		mInputBitSize = numBits;

		double best = (999999999999999.0);

		for (u64 maxBin = 15; maxBin < 40; maxBin++)
		{
			u64 binsHigh = n * 2;
			u64 binsLow = 1;
			// finds the min number of bins needed to get max occ. to be maxBin

			if (-maxprob(n, binsHigh, maxBin) < secParam)
			{
				// maxBins is too small, skip it.
				continue;
			}


			while (binsHigh != binsLow && binsHigh - 1 != binsLow)
			{
				auto mid = (binsHigh + binsLow) / 2;

				if (-maxprob(n, mid, maxBin) < secParam)
				{
					binsLow = mid;
				}
				else
				{
					binsHigh = mid;
				}
			}

			u64 bins = binsHigh;

			u64 logBinCount = (u64)std::log2(bins);

			double total = bins*(double)maxBin * (double)maxBin * ((double)mInputBitSize - logBinCount);

			if (total < best)
			{
				best = total;
				mBinCount = bins;
				mMaxBinSize = maxBin;
				//Log::out << "##########################################################" << Log::endl;
				//Log::out << n << "  " << bins << "   " << maxBin << "    " << logBinCount << "     " << total << Log::endl;
				//Log::out << "##########################################################" << Log::endl;

			}
		}

		mMtx.reset(new std::mutex[mBinCount]);
		mBins.resize(mBinCount);
		mRepSize = mInputBitSize - (u32)std::log2(mBinCount);
	}

	//void SimpleHasher::preHashedInsertItems(ArrayView<block> mySet, u64 itemIdx)
	//{
	//	for (u64 i = 0; i < mySet.size(); ++i, ++itemIdx)
	//	{
	//		auto& item = mySet[i];


	//		u64 addr = *(u64*)&item % mBinCount;

	//		std::lock_guard<std::mutex> lock(mMtx[addr]);
	//		mBins[addr].emplace_back();
	//		mBins[addr].back() = itemIdx;
	//	}
	//}

	////void SimpleHasher::insertItemsWithPhasing(
	//	ArrayView<block> mySet,  
	//	u64 itemIdx)
	//{
	//	u64 addressbitSize = mInputBitSize - mRepSize;
	//	throw std::runtime_error("not impl");

	//	//SHA1 fSeed;
	//	//fSeed.Update(mHashSeed);
	//	//Log::out << "hash seed     " << mHashSeed << Log::endl;
	//	//Log::out << "mInputBitSize " << mInputBitSize << Log::endl;
	//	//Log::out << "mRepSize      " << mRepSize << Log::endl;
	//	//Log::out << "totalRepSize  " << totalRepSize << Log::endl << Log::endl;

	//	u8 xrHash[SHA1::HashSize];

	//	SHA1 f;

	//	//for (u64 i = 0; i < mySet.size(); ++i)
	//	//{
	//	//	auto& item = mySet[i];
	//	//	//Log::out << "  item[" << i << "] " << item << Log::endl;

	//	//	//u64 xr(0),xl(0);

	//	//	//memccpy(&xr, &item, )

	//	//	//BitVector xr;
	//	//	//xr.append((u8*)&item, mRepSize);

	//	//	//BitVector xl;
	//	//	//xl.append((u8*)&item, addressbitSize, xr.size());
	//	//	auto xr = item / mBinCount;
	//	//	auto xl = item % mBinCount;

	//	//	//auto f = fSeed;

	//	//	f.Reset();
	//	//	f.Update(mHashSeed);
	//	//	f.Update((u8*)&xr, sizeof(u64));
	//	//	f.Final(xrHash);

	//	//	//u64 xlVal = 0;
	//	//	//memcpy(&xlVal, xl.data(), xl.sizeBytes());

	//	//	u64 xrHashVal = *(u64*)xrHash % mBinCount;

	//	//	auto addr = (xl + xrHashVal) % mBinCount;

	//	//	//Log::out << "     xr   " << xr << Log::endl;
	//	//	//Log::out << "     xl   " << xl << Log::endl;
	//	//	//Log::out << "     addr " << addr <<  Log::endl;

	//	//	BitVector val(mRepSize);
	//	//	memcpy(val.data(), &xr, std::min(sizeof(xr), val.sizeBytes()));

	//	//	std::lock_guard<std::mutex> lock(mMtx[addr]);
	//	//	mBins[addr].first.push_back(i);
	//	//	mBins[addr].second.emplace_back(std::move(val));

	//	//	//if (i == 0)
	//	//	//{
	//	//	//	Log::out << Log::lock << item << "  -> addr = " << addr << "  val = " << xr << "  (" << mBins[addr].second.back() << ")" << Log::endl << Log::unlock;
	//	//	//}
	//	//}
	//}
}
