#include "CuckooIndex2.h"
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Log.h>
#include <numeric>
#include <random>
#include <algorithm>
#include <mutex>

#define BATCH_SIZE 8

namespace osuCrypto
{


	template<CuckooTypes Mode>
	CuckooIndex2<Mode>::CuckooIndex2()
		:mTotalTries(0)
	{ }

	template<CuckooTypes Mode>
	CuckooIndex2<Mode>::~CuckooIndex2()
	{
	}

	template<CuckooTypes Mode>
	bool CuckooIndex2<Mode>::operator==(const CuckooIndex2 & cmp) const
	{
		if (mBins.size() != cmp.mBins.size())
			throw std::runtime_error("");

		if (mStash.size() != cmp.mStash.size())
			throw std::runtime_error("");



		for (u64 i = 0; i < mBins.size(); ++i)
		{
			if (mBins[i].load() != cmp.mBins[i].load())
			{
				return false;
			}
		}

		for (u64 i = 0; i < mStash.size(); ++i)
		{
			if (mStash[i].load() != cmp.mStash[i].load())
			{
				return false;
			}
		}

		return true;
	}

	template<CuckooTypes Mode>
	bool CuckooIndex2<Mode>::operator!=(const CuckooIndex2 & cmp) const
	{
		return !(*this == cmp);
	}

	template<CuckooTypes Mode>
	void CuckooIndex2<Mode>::print() const
	{

		std::cout << "Cuckoo Hasher  " << std::endl;


		for (u64 i = 0; i < mBins.size(); ++i)
		{
			std::cout << "Bin #" << i;

			if (mBins[i].isEmpty())
			{
				std::cout << " - " << std::endl;
			}
			else
			{
				std::cout << "    c_idx=" << mBins[i].idx() << "  hIdx=" << mBins[i].hashIdx() << std::endl;

			}

		}
		for (u64 i = 0; i < mStash.size() && mStash[i].isEmpty() == false; ++i)
		{
			std::cout << "Bin #" << i;

			if (mStash[i].isEmpty())
			{
				std::cout << " - " << std::endl;
			}
			else
			{
				std::cout << "    c_idx=" << mStash[i].idx() << "  hIdx=" << mStash[i].hashIdx() << std::endl;

			}

		}
		std::cout << std::endl;

	}

	template<CuckooTypes Mode>
	CuckooParam CuckooIndex2<Mode>::selectParams(const u64& n, const u64& statSecParam, const u64& stashSize, const u64& hh)
	{
		double nn = std::log2(n);

		auto h = hh ? hh : 3;

		if (stashSize == 0 && h == 3)
		{
			// parameters that have been experimentally determined.
			double aMax = 123.5;
			double bMax = -130;
			double aSD = 2.3;
			double bSD = 2.18;
			double aMean = 6.3;
			double bMean = 6.45;

			// slope = 123.5 - some small terms when nn < 12.
			double a = aMax / 2 * (1 + erf((nn - aMean) / (aSD * std::sqrt(2))));
			// y-intercept = -130 - nn + some small terms when nn < 12.
			double b = bMax / 2 * (1 + erf((nn - bMean) / (bSD * std::sqrt(2)))) - nn;
			// small terms follow the integrel of the normal distribution.

			// we have the statSecParam = a e + b, where e = |cuckoo|/|set| is the expenation factor
			// therefore we have that
			//
			//   e = (statSecParam - b) / a
			//
			return CuckooParam{ 0,(statSecParam - b) / a, 3, n };
		}
		else if (h == 2)
		{
			// parameters that have been experimentally determined.
			double
				a = -0.8,
				b = 3.3,
				c = 2.5,
				d = 14,
				f = 5,
				g = 0.65;

			// for e > 8,   statSecParam = (1 + 0.65 * stashSize) (b * std::log2(e) + a + nn).
			// for e < 8,   statSecParam -> 0 at e = 2. This is what the pow(...) does...
			auto sec = [&](double e) { return (1 + g * stashSize)*(b * std::log2(e) + a + nn - (f * nn + d) * std::pow(e, -c)); };

			// increase e util we have large enough security.
			double e = 1;
			double s = 0;
			while (s < statSecParam)
			{
				e += 1;
				s = sec(e);
			}

			return CuckooParam{ 0, e, 2, n };
		}

		throw std::runtime_error(LOCATION);

	}

	template<CuckooTypes Mode>
	void CuckooIndex2<Mode>::init(const u64& n, const u64& statSecParam, u64 stashSize, u64 h)
	{
		init(selectParams(n, statSecParam, stashSize, h));
	}

	template<CuckooTypes Mode>
	void CuckooIndex2<Mode>::init(const CuckooParam & params)
	{
		mParams = params;

		if (CuckooIndex2_MAX_HASH_FUNCTION_COUNT < params.mNumHashes)
			throw std::runtime_error("parameters exceeded the maximum number of hash functions are are supported. see getHash(...); " LOCATION);

		mHashes.resize(mParams.mN, AllOneBlock);
		u64 binCount = u64(mParams.mBinScaler * mParams.mN);
		mBins.resize(binCount);
		mStash.resize(mParams.mStashSize);

		mPrng.SetSeed(ZeroBlock);
		//mRandHashIdx.resize(100);
		//for (u64 i = 1; i < mRandHashIdx.size(); ++i)
		//{
		//	if (mParams.mRandomized)
		//	{
		//		mRandHashIdx[i] = mPrng.get<u8>() % (mParams.mNumHashes - 1);
		//		if (mRandHashIdx[i] >= mRandHashIdx[i - 1])
		//			++mRandHashIdx[i];
		//	}
		//	else
		//	{
		//		mRandHashIdx[i] = i % mParams.mNumHashes;
		//	}
		//}
	}


	template<CuckooTypes Mode>
	void CuckooIndex2<Mode>::insert(span<block> items, block hashingSeed, u64 startIdx)
	{
		//if (Mode == CuckooTypes::ThreadSafe) std::cout << "ThreadSafe" << std::endl;
		//if (Mode == CuckooTypes::NotThreadSafe) std::cout << "NotThreadSafe" << std::endl;

		std::array<block, 16> hashs;
		std::array<u64, 16> idxs;
		AES hasher(hashingSeed);

		for (u64 i = 0; i < u64(items.size()); i += u64(hashs.size()))
		{
			auto min = std::min<u64>(items.size() - i, hashs.size());

			hasher.ecbEncBlocks(items.data() + i, min, hashs.data());

			for (u64 j = 0, jj = i; j < min; ++j, ++jj)
			{
				idxs[j] = jj + startIdx;
				hashs[j] = hashs[j] ^ items[jj];

				//if(jj < 1) std::cout<< IoStream::lock << "item[" << jj << "] = " <<items[jj]<<" -> " << hashs[j] << std::endl << IoStream::unlock;
			}

			insert(min, idxs.data(), hashs.data());
		}
	}

    template<CuckooTypes Mode>
    void CuckooIndex2<Mode>::insert(span<block> items,u64 startIdx)
    {
        std::array<u64, 16> idxs;

        for (u64 i = 0; i < u64(items.size()); i += u64(idxs.size()))
        {

            auto min = std::min<u64>(items.size() - i, idxs.size());
            for (u64 j = 0, jj = i; j < min; ++j, ++jj)
            {
                idxs[j] = jj + startIdx;
            }

            insert(min, idxs.data(), items.data() + i);
        }
    }


	template<CuckooTypes Mode>
	void CuckooIndex2<Mode>::insert(const u64& inputIdx, const block& hashs)
	{
		insert(1, &inputIdx, &hashs);
	}

	template<CuckooTypes Mode>
	void CuckooIndex2<Mode>::insert(
		span<u64> inputIdxs,
		span<block> hashs)
	{
#ifndef NDEBUG
		if (inputIdxs.size() != hashs.size())
			throw std::runtime_error("" LOCATION);
#endif

		insert(inputIdxs.size(), inputIdxs.data(), hashs.data());
	}

	template<CuckooTypes Mode>
	u8 CuckooIndex2<Mode>::minCollidingHashIdx(u64 target, block& hashes, u8 numHashFunctions, u64 numBins)
	{
		for (u64 i = 0; i < numHashFunctions; ++i)
		{
			if (target == getHash2(hashes, i, numBins))
				return u8(i);
		}
		return -1;
	}

	template<CuckooTypes Mode>
	void CuckooIndex2<Mode>::insert(
		const u64& sizeMaster,
		const u64* inputIdxsMaster,
		const block* hashsMaster)
	{
		//for (u64 i = 0; i < sizeMaster; ++i)
		//{
		//	u64 inputIdx = inputIdxsMaster[i];
		//	u64 curHashIdx = 0;
		//	mHashes[inputIdx] = hashsMaster[i];

		//	u64 tryCount = 0;
		//	while (tryCount < mReinsertLimit)
		//	{
		//		auto curAddr = getHash(inputIdx, curHashIdx);// (mHashes.data() + inputIdxs[i] * width)[curHashIdxs[i]] % mBins.size();

		//		u64 newVal = inputIdx | (curHashIdx << 56);
		//		auto oldVal = mBins[curAddr].exchange(newVal);

		//		if (oldVal != ~0ull)
		//		{
		//			++tryCount;
		//			curHashIdx = ((oldVal >> 56) + 1) % mParams.mNumHashes;
		//			inputIdx = oldVal & (u64(-1) >> 8);
		//		}
		//		else
		//		{
		//			break;
		//			//tryCount = mReinsertLimit;
		//		}
		//	}

		//	if (tryCount == mReinsertLimit)
		//	{
		//		u64 j = 0;
		//		while (mStash[j].idx() < mParams.numBins())
		//			++j;

		//		mStash[j].swap(inputIdx, curHashIdx);
		//	}
		//	//insert(inputIdxsMaster[i], hashsMaster[i]);
		//}
		//return;

		std::array<u64, BATCH_SIZE> curHashIdxs, curAddrs, oldVals, inputIdxs;
		auto stepSize = BATCH_SIZE;
		//std::vector<u64> curHashIdxs(sizeMaster), curAddrs(sizeMaster), oldVals(sizeMaster), inputIdxs(sizeMaster);
		//auto stepSize = sizeMaster;

		for (u64 step = 0; step < (sizeMaster + stepSize - 1) / stepSize; ++step)
		{
			u64 size = std::min<u64>(sizeMaster - step * stepSize, stepSize);
			u64 remaining = size;
			u64 tryCount = 0;

			//auto inputIdxs = inputIdxsMaster + stepSize * step;
			auto hashs = hashsMaster + stepSize * step;

			for (u64 i = 0; i < size; ++i)
			{

				inputIdxs[i] = inputIdxsMaster[stepSize * step + i];
#ifndef NDEBUG
				if (neq(mHashes[inputIdxs[i]], AllOneBlock))
				{
					std::cout << IoStream::lock << "cuckoo index " << inputIdxs[i] << " already inserted" << std::endl << IoStream::unlock;
					throw std::runtime_error(LOCATION);
				}
#endif // ! NDEBUG

				mHashes[inputIdxs[i]] = hashs[i];
				curHashIdxs[i] = 0;
			}


			while (remaining && tryCount++ < mReinsertLimit)
			{

				// this data fetch can be slow (after the first loop).
				// As such, lets do several fetches in parallel.
				for (u64 i = 0; i < remaining; ++i)
				{
					//curAddrs[i] = mHashes[inputIdxs[i]][curHashIdxs[i]] % mBins.size();
					curAddrs[i] = getHash(inputIdxs[i], curHashIdxs[i]);// (mHashes.data() + inputIdxs[i] * width)[curHashIdxs[i]] % mBins.size();

					//if (inputIdxs[i] == 8)
						//std::cout << i << " * idx " << inputIdxs[i] << "  addr " << curAddrs[i] << std::endl;
				}

				// same thing here, this fetch is slow. Do them in parallel.
				for (u64 i = 0; i < remaining; ++i)
				{
					u64 newVal = inputIdxs[i] | (curHashIdxs[i] << 56);
					oldVals[i] = mBins[curAddrs[i]].exchange(newVal);

					//if (inputIdxs[i] == 8)
					//{

					//	u64 oldIdx = oldVals[i] & (u64(-1) >> 8);
					//	u64 oldHash = (oldVals[i] >> 56);
					//	std::cout
					//		<< i << " * bin[" << curAddrs[i] << "]  "
					//		<< " gets (" << inputIdxs[i] << ", " << curHashIdxs[i] << "),"
					//		<< " evicts (" << oldIdx << ", " << oldHash << ")" << std::endl;
					//}
				}
				// this loop will update the items that were just evicted. The main
				// idea of that our array looks like
				//     |XW__Y____Z __|
				// For X and W, which failed to be placed, lets write over them
				// with the vaues that they evicted.
				u64 putIdx = 0, getIdx = 0;
				while (putIdx < remaining && oldVals[putIdx] != u64(-1))
				{
					inputIdxs[putIdx] = oldVals[putIdx] & (u64(-1) >> 8);
					auto  h = (oldVals[putIdx] >> 56);

					if (0)
					{
						auto h2 = mPrng.get<u8>() % (mParams.mNumHashes - 1);
						if (h2 >= h)
							++h2;
						curHashIdxs[putIdx] = h2;
					}
					else
						curHashIdxs[putIdx] = (1 + h) % mParams.mNumHashes;
					++putIdx;
				}

				getIdx = putIdx + 1;

				// Now we want an array that looks like
				//  |ABCD___________| but currently have
				//  |AB__Y_____Z____| so lets move them
				// forward and replace Y, Z with the values
				// they evicted.
				while (getIdx < remaining)
				{
					while (getIdx < remaining &&
						oldVals[getIdx] == u64(-1))
						++getIdx;

					if (getIdx >= remaining) break;

					inputIdxs[putIdx] = oldVals[getIdx] & (u64(-1) >> 8);
					//curHashIdxs[putIdx] = (1 + (oldVals[getIdx] >> 56)) % mParams.mNumHashes;
					auto  h = (oldVals[getIdx] >> 56);
					if (0)
					{

						auto h2 = mPrng.get<u8>() % (mParams.mNumHashes - 1);
						if (h2 >= h)
							++h2;
						//lout << int(h) << " -> " << int(h2) << std::endl;
						curHashIdxs[putIdx] = h2;
					}
					else
						curHashIdxs[putIdx] = (1 + h) % mParams.mNumHashes;

					// not needed. debug only
					//std::swap(oldVals[putIdx], oldVals[getIdx]);

					++putIdx;
					++getIdx;
				}

				remaining = putIdx;
			}

			// put any that remain in the stash.
			for (u64 i = 0, j = 0; i < remaining; ++j)
			{
				if (j >= mStash.size())
				{
					std::cout << "cuckoo stash overflow" << std::endl;

					auto jj = find(mHashes[inputIdxs[i]]);
					if (jj)
					{
						std::cout << "already inserted." << std::endl;
					}

					throw std::runtime_error(LOCATION);
				}

				mStash[j].swap(inputIdxs[i], curHashIdxs[i]);

				if (inputIdxs[i] == u64(-1) >> 8)
					++i;
			}

		}

	}

	template<CuckooTypes Mode>
	u64 CuckooIndex2<Mode>::getHash(const u64& inputIdx, const u64& hashIdx)
	{
		return CuckooIndex2<Mode>::getHash2(mHashes[inputIdx], hashIdx, mBins.size());
	}

	namespace
	{


	// LUTs
	std::size_t num_of_luts_ = 5;
	std::size_t num_of_tables_in_lut_ = 32;
	std::size_t elem_byte_length_ = 8;
	std::vector<std::vector<std::vector<std::uint64_t>>> luts_;
	std::mutex mtx_lut;
	}

	template<CuckooTypes Mode>
	u64 CuckooIndex2<Mode>::getHash2(const block& hash, const u8& hashIdx, u64 num_bins)
	{

		static_assert(CuckooIndex2_MAX_HASH_FUNCTION_COUNT < 5,
			"here we assume that we dont overflow the 16 byte 'block hash'. "
			"To assume that we can have at most 4 has function, i.e. we need  2*hashIdx + sizeof(u64) < sizeof(block)");
		return *(u64*)(((u8*)&hash) + (2 * hashIdx)) % num_bins;

		AES aes(block(0, hashIdx));
		auto h = aes.ecbEncBlock(hash);
		return (*(u64*)&h) % num_bins;

		if (luts_.size() == 0)
		{
			std::lock_guard<std::mutex> lock(mtx_lut);
			if (luts_.size() == 0)
			{
				std::mt19937_64 generator_(0);

				luts_.resize(CuckooIndex2_MAX_HASH_FUNCTION_COUNT);
				for (auto& luts : luts_) {
					luts.resize(num_of_luts_);
					for (auto& entry : luts) {
						entry.resize(num_of_tables_in_lut_);
					}
				}

				for (auto i = 0ull; i < CuckooIndex2_MAX_HASH_FUNCTION_COUNT; ++i) {
					for (auto j = 0ull; j < num_of_luts_; ++j) {
						for (auto k = 0ull; k < num_of_tables_in_lut_; k++) {
							luts_.at(i).at(j).at(k) = generator_();
						}
					}
				}
			}
		}

		std::uint64_t address = hash.as<u64>()[0];
		for (auto lut_i = 0ull; lut_i < num_of_luts_; ++lut_i) {
			std::size_t lut_id = ((address >> (lut_i * elem_byte_length_ / num_of_luts_)) & 0x000000FFu);
			lut_id %= num_of_tables_in_lut_;
			address ^= luts_.at(hashIdx).at(lut_i).at(lut_id);
		}

		return address % num_bins;



		return *(u64*)(((u8*)&hash) + (2 * hashIdx)) % num_bins;
	}


	template<CuckooTypes Mode>
    typename CuckooIndex2<Mode>::FindResult CuckooIndex2<Mode>::find(const block& hashes)
	{
		if (mParams.mNumHashes == 2)
		{
			std::array<u64, 2>  addr{
				getHash2(hashes, 0, mBins.size()),
				getHash2(hashes, 1, mBins.size()) };

			std::array<u64, 2> val{
				mBins[addr[0]].load(),
				mBins[addr[1]].load() };

			if (val[0] != u64(-1))
			{
				u64 itemIdx = val[0] & (u64(-1) >> 8);

				bool match = eq(mHashes[itemIdx], hashes);

                if (match) return { itemIdx, addr[0] };
			}

			if (val[1] != u64(-1))
			{
				u64 itemIdx = val[1] & (u64(-1) >> 8);

				bool match = eq(mHashes[itemIdx], hashes);

				if (match) return { itemIdx, addr[1] };
			}


			// stash
			u64 i = 0;
			while (i < mStash.size() && mStash[i].isEmpty() == false)
			{
				u64 val = mStash[i].load();
				if (val != u64(-1))
				{
					u64 itemIdx = val & (u64(-1) >> 8);

					bool match = eq(mHashes[itemIdx], hashes);

					if (match)
					{
						return { itemIdx, i + mBins.size() };
					}
				}

				++i;
			}

		}
		else
		{

			for (u64 i = 0; i < mParams.mNumHashes; ++i)
			{
				u64 xrHashVal = getHash2(hashes, i, mBins.size());
				auto addr = (xrHashVal) % mBins.size();


				u64 val = mBins[addr].load();

				if (val != u64(-1))
				{
					u64 itemIdx = val & (u64(-1) >> 8);

					bool match = eq(mHashes[itemIdx], hashes);

					if (match)
					{
                        return { itemIdx, addr };
					}
				}
			}

			u64 i = 0;
			while (i < mStash.size() && mStash[i].isEmpty() == false)
			{
				u64 val = mStash[i].load();

				if (val != u64(-1))
				{
					u64 itemIdx = val & (u64(-1) >> 8);

					bool match = eq(mHashes[itemIdx], hashes);

					if (match)
					{
						return { itemIdx, i + mBins.size() };
					}
				}

				++i;
			}
		}

        return {~0ull,~0ull};
	}


	template<CuckooTypes Mode>
	void CuckooIndex2<Mode>::find(
		span<block> hashes,
		span<u64> idxs)
	{
#ifndef NDEBUG
		if (hashes.size() != idxs.size())
			throw std::runtime_error(LOCATION);
#endif

		find(hashes.size(), hashes.data(), idxs.data());
	}




	template<CuckooTypes Mode>
	void CuckooIndex2<Mode>::find(const u64& numItemsMaster, const block * hashesMaster, const u64 * idxsMaster)
	{
		std::array<std::array<u64, 2>, BATCH_SIZE> findVal;
		std::array<u64, BATCH_SIZE> idxs;
		//std::array<block, BATCH_SIZE> idxs;


		for (u64 step = 0; step < (numItemsMaster + findVal.size() - 1) / findVal.size(); ++step)
		{
			auto numItems = std::min<u64>(numItemsMaster - findVal.size() * step, findVal.size());

			//auto idxs = idxsMaster + step * findVal.size();
			memcpy(idxs.data(), idxsMaster + step * findVal.size(), sizeof(u64) * BATCH_SIZE);
			auto hashes = hashesMaster + step * findVal.size();

			if (mParams.mNumHashes == 2)
			{
				std::array<u64, 2>  addr;

				for (u64 i = 0; i < numItems; ++i)
				{
					idxs[i] = -1;

					addr[0] = getHash2(hashes[i], 0, mBins.size());
					addr[1] = getHash2(hashes[i], 1, mBins.size());

					findVal[i][0] = mBins[addr[0]].load();
					findVal[i][1] = mBins[addr[1]].load();
				}

				for (u64 i = 0; i < numItems; ++i)
				{
					if (findVal[i][0] != u64(-1))
					{
						u64 itemIdx = findVal[i][0] & (u64(-1) >> 8);
						bool match = eq(mHashes[itemIdx], hashes[i]);
                        if (match)
                        {
                            idxs[i] = itemIdx;
                        }
					}

					if (findVal[i][1] != u64(-1))
					{
						u64 itemIdx = findVal[i][1] & (u64(-1) >> 8);
						bool match = eq(mHashes[itemIdx], hashes[i]);
						if (match) idxs[i] = itemIdx;
					}
				}

				// stash

				u64 i = 0;
				while (i < mStash.size() && mStash[i].isEmpty() == false)
				{
					u64 val = mStash[i].load();
					if (val != u64(-1))
					{
						u64 itemIdx = val & (u64(-1) >> 8);

						for (u64 j = 0; j < numItems; ++j)
						{
							bool match = eq(mHashes[itemIdx], hashes[i]);
							if (match) idxs[j] = itemIdx;
						}
					}

					++i;
				}
			}
			else
			{
				throw std::runtime_error("not implemented");
			}
		}

	}


	template<CuckooTypes Mode>
	void CuckooIndex2<Mode>::validate(span<block> inputs, block hashingSeed)
	{
		AES hasher(hashingSeed);
		u64 insertCount = 0;

		for (u64 i = 0; i < u64(inputs.size()); ++i)
		{

			block hash = hasher.ecbEncBlock(inputs[i]) ^ inputs[i];

			if (neq(hash, mHashes[i]))
				throw std::runtime_error(LOCATION);

			if (neq(mHashes[i], AllOneBlock))
			{
				++insertCount;
				u64 matches(0);
				std::vector<u64> hashes(mParams.mNumHashes);
				for (u64 j = 0; j < mParams.mNumHashes; ++j)
				{
					auto h = hashes[j] = getHash(i, j);
					auto duplicate = (std::find(hashes.begin(), hashes.begin() + j, h) != (hashes.begin() + j));

					if (duplicate == false && mBins[h].isEmpty() == false && mBins[h].idx() == i)
					{
						++matches;
					}
				}

				if (matches != 1)
					throw std::runtime_error(LOCATION);
			}
		}

		u64 nonEmptyCount(0);
		for (u64 i = 0; i < mBins.size(); ++i)
		{
			if (mBins[i].isEmpty() == false)
				++nonEmptyCount;
		}

		if (nonEmptyCount != insertCount)
			throw std::runtime_error(LOCATION);
	}

	template<CuckooTypes Mode>
	u64 CuckooIndex2<Mode>::stashUtilization() const
	{
		u64 i = 0;
		while (i < mStash.size() && mStash[i].isEmpty() == false)
		{
			++i;
		}

		return i;
	}


	//    bool CuckooIndex2<Mode>::Bin::isEmpty() const
	//    {
	//        return mVal == u64(-1);
	//    }
	//
	//    u64 CuckooIndex2<Mode>::Bin::idx() const
	//    {
	//        return mVal  & (u64(-1) >> 8);
	//    }
	//
	//    u64 CuckooIndex2<Mode>::Bin::hashIdx() const
	//    {
	//        return mVal >> 56;
	//    }
	//
	//    void CuckooIndex2<Mode>::Bin::swap(u64 & idx, u64 & hashIdx)
	//    {
	//        u64 newVal = idx | (hashIdx << 56);
	//#ifdef THREAD_SAFE_CUCKOO
	//        u64 oldVal = mVal.exchange(newVal, std::memory_order_relaxed);
	//#else
	//        u64 oldVal = mVal;
	//        mVal = newVal;
	//#endif
	//        if (oldVal == u64(-1))
	//        {
	//            idx = hashIdx = u64(-1);
	//        }
	//        else
	//        {
	//            idx = oldVal & (u64(-1) >> 8);
	//            hashIdx = oldVal >> 56;
	//        }
	//    }


	template class CuckooIndex2<ThreadSafe>;
	template class CuckooIndex2<NotThreadSafe>;
}
