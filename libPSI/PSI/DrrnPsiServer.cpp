#include "DrrnPsiServer.h"
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <libPSI/PIR/BgiPirServer.h>
#include <libPSI/Tools/SimpleIndex.h>
#include <algorithm>
namespace osuCrypto
{
	void DrrnPsiServer::init(u8 serverId, Channel clientChl, Channel srvChl, u64 serverSetSize, u64 clientSetSize, block seed, double binScaler)
	{

	}


	void DrrnPsiServer::init(u8 serverId, span<Channel> chls, Channel srvChl, u64 serverSetSize, u64 clientSetSize, block seed, double binScaler)
	{
		if (mServerId == 0) gTimer.setTimePoint("DrrnSrv init start");
		auto ssp(40);
		mPrng.SetSeed(seed);
		mClientSetSize = clientSetSize;
		mServerSetSize = serverSetSize;
		mServerId = serverId;

		if (mIndex.mParams.mN != serverSetSize)
			throw std::runtime_error(LOCATION);

		//setCuckooParam(serverSetSize, ssp);


		u64 numBalls = clientSetSize * mIndex.mParams.mNumHashes;
		mNumSimpleBins = std::max<u64>(1, static_cast<u64>((numBalls / log2floor(numBalls)) * binScaler));

		if (mServerId == 0) gTimer.setTimePoint("DrrnSrv balls_bins start");
		mBinSize = SimpleIndex::get_bin_size(mNumSimpleBins, numBalls, ssp);



		if (serverId == 0)
		{
			otSend.resize(chls.size());
			mPsi.resize(chls.size());
			for (u64 i = 0; i < chls.size(); ++i)
			{
				{
					otSend[i].configure(false, 40, 128);
					PRNG sharedPrng(toBlock(44444));
					std::vector<std::array<block, 2>> sendBlks(otSend[i].getBaseOTCount());
					sharedPrng.get(sendBlks.data(), sendBlks.size());

					BitVector choices(otSend[i].getBaseOTCount());
					choices.randomize(sharedPrng);
					std::vector<block> recvBlks(otSend[i].getBaseOTCount());
					for (u64 i = 0; i < choices.size(); ++i)
						recvBlks[i] = sendBlks[i][choices[i]];

					otSend[i].setBaseOts(recvBlks, choices);
				}

				// i think these are the right set sizes for the final PSI
				auto serverPsiInputSize = mBinSize * mNumSimpleBins;
				auto clientPsiInputSize = clientSetSize * mIndex.mParams.mNumHashes;
				mPsi[i].init(serverPsiInputSize, clientPsiInputSize, 40, chls[i], otSend[i], mPrng.get<block>());
			}
		}

		if (mServerId == 0) gTimer.setTimePoint("DrrnSrv init end");

	}


	//void DrrnPsiServer::setCuckooParam(osuCrypto::u64 &serverSetSize, int ssp)
	//{
	//	u64 h = 2;
	//	mIndex.init(CuckooIndex<>::selectParams(serverSetSize, ssp, true, h));
	//}

	void DrrnPsiServer::setInputs(span<block> inputs, u64 numHash, u64 ssp, u64 byteSize)
	{
		if (numHash != 2 && numHash != 3)
		{
			std::cout << "#hash must be in {2,3}. Provided h=" << numHash << std::endl;
			throw std::runtime_error(LOCATION);
		}

		if (byteSize > 16) throw std::runtime_error(LOCATION);
		mByteSize = byteSize;
		mHashingSeed = ZeroBlock; // todo, make random;
		if (mIndex.mBins.size()) throw std::runtime_error(LOCATION);
		mIndex.init(CuckooIndex<>::selectParams(inputs.size(), ssp, true, numHash));
		//std::cout << mIndex.mParams.mN << " " << mIndex.mParams.mBinScaler << std::endl;

		mIndex.insert(inputs, mHashingSeed);

		//mInputs = inputs;
#if  ITEM_SIZE == 128
		if (mByteSize != 16)
		{
			std::cout << "wrong compile time byte size (should be 16) " LOCATION << std::endl;
			throw std::runtime_error("wrong compile time byte size (should be 16) " LOCATION);
		}
		mCuckooData.resize(mIndex.mBins.size());
#elif ITEM_SIZE == 64
		if (mByteSize != 8)
		{
			std::cout << "wrong compile time byte size (should be 8) " LOCATION << std::endl;
			throw std::runtime_error("wrong compile time byte size (should be 8) " LOCATION);
		}
		mCuckooData.resize(mIndex.mBins.size());
#else
		mCuckooData.resize(mIndex.mBins.size(), mByteSize);
		auto destIter = mCuckooData.data();
#endif

		for (u64 i = 0; i < mIndex.mBins.size(); ++i)
		{
			auto& item = mIndex.mBins[i];
			auto empty = item.isEmpty();
			if (empty == false)
			{
				auto idx = item.idx();
#if  ITEM_SIZE == 128
				mCuckooData[i] = inputs[idx];
#elif ITEM_SIZE == 64
				memcpy(&mCuckooData[i], &inputs[idx], mByteSize);
#else
				memcpy(destIter, &inputs[idx], mByteSize);
#endif
			}

#ifndef ITEM_SIZE
			destIter += mByteSize;
#endif
		}

#ifndef NDEBUG
		mIndex.validate(inputs, mHashingSeed);
#endif
	}


	void DrrnPsiServer::send(Channel clientChl, Channel srvChl, u64 numThreads)
	{
		send(span<Channel>(&clientChl, 1), srvChl, numThreads);
	}

	void DrrnPsiServer::send(span<Channel> clientChls, Channel srvChl, u64 numThreads)
	{
		//numThreads = 1;
		if (numThreads == 0) numThreads = std::thread::hardware_concurrency();
		auto numClients = clientChls.size();

		u64 cuckooSlotsPerBin = (mIndex.mBins.size() + mNumSimpleBins) / mNumSimpleBins;

		if (mServerId == 0) gTimer.setTimePoint("DrrnSrv send start");

		// power of 2
		u64 numLeafBlocksPerBin = (cuckooSlotsPerBin + 127) / 128;
		u64 gDepth = 2;
		u64 kDepth = std::max<u64>(gDepth, log2floor(numLeafBlocksPerBin)) - gDepth;
		u64 groupSize = (numLeafBlocksPerBin + (u64(1) << kDepth) - 1) / (u64(1) << kDepth);
		if (groupSize > 8) throw     std::runtime_error(LOCATION);
		std::vector<block> shares(mNumSimpleBins * mBinSize * numClients, ZeroBlock);

		u64 keySize = kDepth + 1 + groupSize;
		Matrix<std::future<u64>> futrs(numClients, mNumSimpleBins);


		Matrix<block> ks(mNumSimpleBins * mBinSize * numClients, keySize);
		auto step2 = mBinSize * keySize;
		auto step = mNumSimpleBins * step2;
		auto ksIter = ks.data();
		for (u64 i = 0; i < numClients; ++i)
		{
			auto kIter = ks.data() + step2 * i;
			for (u64 bIdx = 0; bIdx < futrs.size(); ++bIdx)
			{
				futrs(i, bIdx) = clientChls[i].asyncRecv(kIter, step2);
				kIter += step;
			}
		}


		//u64 cuckooIdx = 0;
		auto routine = [this, numThreads, kDepth, keySize, groupSize, numClients, &futrs, &ks, &shares](u64 tIdx)
		{
			for (u64 binIdx = tIdx; binIdx < mNumSimpleBins; binIdx += numThreads)
			{

				auto cuckooIdx = (binIdx * mIndex.mBins.size() + mNumSimpleBins - 1) / mNumSimpleBins;
				auto cuckooEnd = ((binIdx + 1) * mIndex.mBins.size() + mNumSimpleBins - 1) / mNumSimpleBins;


				for (u64 i = 0; i < numClients; ++i)
					futrs(i, binIdx).get();

				BgiPirServer::MultiKey mk;
				auto numKeys = (mBinSize * numClients);
				mk.init(numKeys, kDepth + 1, groupSize);


				auto kIter = ks.data() + binIdx * keySize * numKeys;


				for (u64 i = 0; i < numKeys; ++i)
				{
					span<block> kk(kIter, kDepth + 1);
					span<block> g(kIter + kDepth + 1, groupSize);
					mk.setKey(i, kk, g);
					kIter += keySize;
				}

#if  ITEM_SIZE == 128 ||  ITEM_SIZE == 64
				block* __restrict cuckooIter = mCuckooData.data() + cuckooIdx;
#else
				u8* __restrict cuckooIter = mCuckooData[cuckooIdx].data();
#endif
				std::array<block, 8> masks;
				auto numSteps = numKeys / 8;
				for (u64 i = 0; cuckooIdx < cuckooEnd; ++i, ++cuckooIdx)
				{
					auto& item = mIndex.mBins[cuckooIdx];
					auto bits = mk.yeild();

					auto empty = item.isEmpty();
					if (empty == false)
					{
#if  ITEM_SIZE == 128
						block pirData_i = *cuckooIter;
#elif ITEM_SIZE == 64
						block pirData_i(toBlock(*cuckooIter));
#else
						block pirData_i(ZeroBlock);
						memcpy(&pirData_i, cuckooIter, mByteSize);
#endif

						auto bitsIter = bits.data();
						auto shareIter = shares.data() + binIdx * numKeys;


						masks[0] = zeroAndAllOne[bitsIter[0]];
						masks[1] = zeroAndAllOne[bitsIter[1]];
						masks[2] = zeroAndAllOne[bitsIter[2]];
						masks[3] = zeroAndAllOne[bitsIter[3]];
						masks[4] = zeroAndAllOne[bitsIter[4]];
						masks[5] = zeroAndAllOne[bitsIter[5]];
						masks[6] = zeroAndAllOne[bitsIter[6]];
						masks[7] = zeroAndAllOne[bitsIter[7]];

						for (u64 j = 0; j < numSteps; ++j)
						{
							shareIter[0] = shareIter[0] ^ (masks[0] & pirData_i);
							shareIter[1] = shareIter[1] ^ (masks[1] & pirData_i);
							shareIter[2] = shareIter[2] ^ (masks[2] & pirData_i);
							shareIter[3] = shareIter[3] ^ (masks[3] & pirData_i);
							shareIter[4] = shareIter[4] ^ (masks[4] & pirData_i);
							shareIter[5] = shareIter[5] ^ (masks[5] & pirData_i);
							shareIter[6] = shareIter[6] ^ (masks[6] & pirData_i);
							shareIter[7] = shareIter[7] ^ (masks[7] & pirData_i);

							bitsIter += 8;
							shareIter += 8;
						}

						for (u64 j = 0; j < numKeys % 8; ++j)
						{
							shareIter[j] = shareIter[j] ^ (zeroAndAllOne[bitsIter[j]] & pirData_i);
						}
					}
#if  ITEM_SIZE == 128 || ITEM_SIZE == 64
					++cuckooIter;
#else
					cuckooIter += mByteSize;
#endif
				}
			}
		};
		if (mServerId == 0) gTimer.setTimePoint("DrrnSrv PSI start");

		std::vector<std::thread> thrds(numThreads - 1);
		for (u64 i = 1; i < numThreads; ++i)
			thrds[i - 1] = std::thread([i, &routine]() { routine(i); });

		routine(0);

		for (u64 i = 1; i < numThreads; ++i)
			thrds[i - 1].join();

		thrds.resize(numClients);
		for (u64 c = 0; c < numClients; ++c)
		{

		//}
		//auto doPSI = [&](u64 c)
		//{
			auto& clientChl = clientChls[c];
			auto& psi = mPsi[c];
			if (mServerId)
			{
				block rSeed;
				clientChl.recv((u8*)&rSeed, sizeof(block));

				PRNG prng(rSeed ^ OneBlock);
				if (shares.size() > (1ull << 32) - 1) throw std::runtime_error(LOCATION);

				std::vector<u32> pi1(shares.size()), sigma(mIndex.mParams.mNumHashes);
				for (u32 i = 0; i < sigma.size(); ++i) sigma[i] = i;
				for (u32 i = 0; i < pi1.size(); ++i) pi1[i] = i;
				std::random_shuffle(pi1.begin(), pi1.end(), prng);

				std::vector<block>
					r(shares.size()),
					s(shares.size()),
					piS1(shares.size()),
					pi1SigmaRS(shares.size());

				AES rGen(rSeed);
				rGen.ecbEncCounterMode(shares.size() * 0, shares.size(), r.data());
				rGen.ecbEncCounterMode(shares.size() * 1, shares.size(), piS1.data());
				rGen.ecbEncCounterMode(shares.size() * 2, shares.size(), s.data());

				auto rIter = r.begin();
				for (u64 i = 0; i < mClientSetSize; ++i)
				{
					std::random_shuffle(sigma.begin(), sigma.end(), prng);
					for (u64 j = 1; j < sigma.size(); ++j)
					{
						std::swap(rIter[j], rIter[sigma[j]]);
					}
					rIter += sigma.size();
				}

				for (u64 i = 0; i < pi1SigmaRS.size(); ++i)
				{
					auto pi1i = pi1[i];
					pi1SigmaRS[i] = r[pi1i] ^ s[pi1i];
					//std::cout << "pi1(r + s)[" << i << "] " << pi1SigmaRS[i] << " = " << r[pi1i]<<" ^ "<<s[pi1i] << std::endl;
				}
				srvChl.asyncSend(std::move(pi1SigmaRS));

				auto piSIter = piS1.begin();
				for (u64 j = 0; piSIter != piS1.end(); ++piSIter, ++j)
				{
					shares[j] = shares[j] ^ *piSIter;
				}

				srvChl.asyncSend(std::move(shares));
				//srvChl.asyncSend(std::move(piS1));
			}
			else
			{
				std::vector<u32> pi0(shares.size());
				std::vector<block> piS0(shares.size()), pi1SigmaRS(shares.size()), piSigmaR0(shares.size());
				clientChl.recv((u8*)pi0.data(), pi0.size() * sizeof(u32));
				clientChl.recv(piS0);

				srvChl.recv((u8*)pi1SigmaRS.data(), pi1SigmaRS.size() * sizeof(block));

				for (u64 i = 0; i < shares.size(); ++i)
				{
					//std::cout << "pi(r + s)[" << i << "]=" << pi1SigmaRS[pi0[i]] << std::endl;
					piSigmaR0[i] = pi1SigmaRS[pi0[i]] ^ piS0[i];
				}

				// reuse the memory
				auto& piSigmaRV1 = pi1SigmaRS;
				srvChl.recv(piSigmaRV1);
				//srvChl.recv(piS1);

				for (u64 i = 0; i < shares.size(); ++i)
				{
					//std::cout << "pi(r)[" << i << "] " << (piS1[i] ^ piSigmaR0[i]) << std::endl;
					shares[i] = shares[i] ^ piSigmaR0[i] ^ piSigmaRV1[i];

					//std::cout << "s i=" << i << " " << (shares[i] ^ (piS0[i] ^ piS1[i])) << " " << (piS0[i] ^ piS1[i]) << " = "
					//    << piS0[i] << " + " << piS1[i] << std::endl;
				}
				//u64  j = 0, end = shares.size() - 7;
				//for (; j < end; j += 8)
				//{
				//    shares[j + 0] = shares[j + 0] ^ otherShare[j + 0];
				//    shares[j + 1] = shares[j + 1] ^ otherShare[j + 1];
				//    shares[j + 2] = shares[j + 2] ^ otherShare[j + 2];
				//    shares[j + 3] = shares[j + 3] ^ otherShare[j + 3];
				//    shares[j + 4] = shares[j + 4] ^ otherShare[j + 4];
				//    shares[j + 5] = shares[j + 5] ^ otherShare[j + 5];
				//    shares[j + 6] = shares[j + 6] ^ otherShare[j + 6];
				//    shares[j + 7] = shares[j + 7] ^ otherShare[j + 7];
				//}
				//for (; j < shares.size(); ++j)
				//{
				//    shares[j] = shares[j] ^ otherShare[j];
				//}

				//for (u64 i = 0; i < shares.size(); ++i)
				//{
				//    std::cout << IoStream::lock << "sshare[" << i << "] = " << shares[i] << std::endl << IoStream::unlock;
				//}
				psi.sendInput(shares, clientChl);
			}

			if (mServerId == 0) gTimer.setTimePoint("DrrnSrv send Done");
		}

	}
}
