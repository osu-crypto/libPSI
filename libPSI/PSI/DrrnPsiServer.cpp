#include "DrrnPsiServer.h"
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <libPSI/PIR/BgiPirServer.h>
#include <libPSI/Tools/SimpleIndex.h>

#include <cryptoTools/Common/Timer.h>
#include <algorithm>
namespace osuCrypto
{
	void DrrnPsiServer::init(u8 serverId, Channel clientChl, Channel srvChl, u64 serverSetSize, u64 clientSetSize, block seed, double binScaler, u64 bigBlockSize)
	{
		if (mServerId == 0) gTimer.setTimePoint("Drrn_Srv.init.start");
		auto ssp(40);
		mPrng.SetSeed(seed);
		mClientSetSize = clientSetSize;
		mServerSetSize = serverSetSize;
		mServerId = serverId;
		mBigBlockSize = bigBlockSize;

		if (mIndex.mParams.mN != serverSetSize)
			throw std::runtime_error(LOCATION);

		//setCuckooParam(serverSetSize, ssp);


		u64 numBalls = clientSetSize * mIndex.mParams.mNumHashes;
		mNumSimpleBins = std::max<u64>(1, (numBalls / log2floor(numBalls)) * binScaler);

		if (mServerId == 0) gTimer.setTimePoint("Drrn_Srv balls_bins start");
		mBinSize = SimpleIndex::get_bin_size(mNumSimpleBins, numBalls, ssp);

		if (mNumSimpleBins == 1 && mBinSize != numBalls)
			throw std::runtime_error(LOCATION);

			auto serverPsiInputSize = mBinSize * mNumSimpleBins * mBigBlockSize;
		if (serverId == 0)
		{
			// i think these are the right set sizes for the final PSI
			auto clientPsiInputSize = clientSetSize * mIndex.mParams.mNumHashes;
			//std::cout << "|ss| "<< serverPsiInputSize << std::endl;
			mPsi.init(serverPsiInputSize, clientPsiInputSize, 40, clientChl, otSend, mPrng.get<block>());

			srvChl.recv(mPi1SigmaRS);
		}
		else
		{
			block rSeed = CCBlock;
			//clientChl.recv((u8*)&rSeed, sizeof(block));

			PRNG prng(rSeed ^ OneBlock);

			std::vector<u32> pi1(serverPsiInputSize), sigma(mIndex.mParams.mNumHashes);
			for (u32 i = 0; i < sigma.size(); ++i) sigma[i] = i;
			for (u32 i = 0; i < pi1.size(); ++i) pi1[i] = i;
			std::random_shuffle(pi1.begin(), pi1.end(), prng);

			std::vector<block>
				r(serverPsiInputSize),
				s(serverPsiInputSize),
				//piS1(serverPsiInputSize),
				pi1SigmaRS(serverPsiInputSize);

			mPiS1.resize(serverPsiInputSize);

			AES rGen(rSeed);
			//memset(r.data(), 0, r.size() * sizeof(block));
			rGen.ecbEncCounterMode(serverPsiInputSize * 0, serverPsiInputSize, r.data());
			rGen.ecbEncCounterMode(serverPsiInputSize * 1, serverPsiInputSize, mPiS1.data());
			rGen.ecbEncCounterMode(serverPsiInputSize * 2, serverPsiInputSize, s.data());

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
		}

		if (mServerId == 0) gTimer.setTimePoint("Drrn_Srv.init.end");

	}

	//void DrrnPsiServer::setCuckooParam(osuCrypto::u64 &serverSetSize, int ssp)
	//{
	//	u64 h = 2;
	//	mIndex.init(CuckooIndex<>::selectParams(serverSetSize, ssp, true, h));
	//}

	void DrrnPsiServer::setInputs(span<block> inputs, u64 numHash, u64 ssp)
	{
		if (numHash != 2 && numHash != 3)
		{
			std::cout << "#hash must be in {2,3}. Provided h=" << numHash << std::endl;
			throw std::runtime_error(LOCATION);
		}


		mHashingSeed = ZeroBlock; // todo, make random;
		if (mIndex.mBins.size()) throw std::runtime_error(LOCATION);
		mIndex.init(CuckooIndex<>::selectParams(inputs.size(), ssp, 0, numHash));
		//std::cout << mIndex.mParams.mN << " " << mIndex.mParams.mBinScaler << std::endl;

		mIndex.insert(inputs, mHashingSeed);

		//mInputs = inputs;
		mCuckooData.resize(mIndex.mBins.size());


		for (u64 i = 0; i < mCuckooData.size(); ++i)
		{
			auto& item = mIndex.mBins[i];
			auto empty = item.isEmpty();
			if (empty == false)
			{
				auto idx = item.idx();
				mCuckooData[i] = inputs[idx];
			}
		}

#ifndef NDEBUG
		mIndex.validate(inputs, mHashingSeed);
#endif
	}


	void DrrnPsiServer::send(Channel clientChl, Channel srvChl, u64 numThreads)
	{
		//numThreads = 1;
		if (numThreads == 0) numThreads = std::thread::hardware_concurrency();


		u64 cuckooSlotsPerBin = (mIndex.mBins.size() + mNumSimpleBins) / mNumSimpleBins;

		if (mServerId == 0) gTimer.setTimePoint("Drrn_Srv.send.start");

		// power of 2
		u64 numLeafBlocksPerBin = (cuckooSlotsPerBin + mBigBlockSize * 128 - 1) / (mBigBlockSize * 128);
		u64 gDepth = 2;
		u64 kDepth = std::max<u64>(gDepth, log2floor(numLeafBlocksPerBin)) - gDepth;
		u64 groupSize = (numLeafBlocksPerBin + (u64(1) << kDepth) - 1) / (u64(1) << kDepth);
		if (groupSize > 8) throw     std::runtime_error(LOCATION);
		std::vector<block> shares(mNumSimpleBins * mBinSize * mBigBlockSize);

		u64 keySize = kDepth + 1 + groupSize;

		//if(mServerId == 0)
		//	std::cout << "|key| " << keySize << std::endl;
		std::vector<std::future<void>> futrs(mNumSimpleBins);
		Matrix<block> k(mNumSimpleBins * mBinSize, keySize);
		//std::vector<u64> idxs(mNumSimpleBins * mBinSize);
		for (u64 bIdx = 0; bIdx < futrs.size(); ++bIdx)
		{
			futrs[bIdx] = clientChl.asyncRecv((u8*)(k.data() + keySize * bIdx * mBinSize), k.stride() * sizeof(block) * mBinSize);
			//futrs[bIdx] = clientChl.asyncRecv(idxs.data() + bIdx * mBinSize, sizeof(u64) * mBinSize);
		}
		//auto fIter = futrs.begin();

		//std::cout << "|cuckoo|: " << mIndex.mBins.size() << std::endl;

		//u64 cuckooIdx = 0;
		auto routine = [this, numThreads, kDepth, keySize, groupSize, &futrs, &k, &shares](u64 tIdx)
		{
			//std::vector<block> pirData((u64(1) << kDepth) * groupSize * 128);
			u64 total = 0;

			for (u64 binIdx = tIdx; binIdx < mNumSimpleBins; binIdx += numThreads)
			{

				//u64 idx = cuckooIdx * mNumSimpleBins / mIndex.mBins.size();

				auto cuckooIdx = (binIdx * mIndex.mBins.size() + mNumSimpleBins - 1) / mNumSimpleBins;
				auto cuckooEnd = ((binIdx + 1) * mIndex.mBins.size() + mNumSimpleBins - 1) / mNumSimpleBins;
				//auto curSize = std::min<u64>(cuckooSlotsPerBin, mIndex.mBins.size() - cuckooIdx);

				futrs[binIdx].get();
				if (mUseSingleDataPass)
				{

					BgiPirServer::MultiKey mk;
					auto kIter = k.data() + keySize * binIdx * mBinSize;

					mk.init(mBinSize, kDepth + 1, groupSize);
					////auto idxIter = idxs.data() + binIdx * mBinSize;
					for (u64 i = 0; i < mBinSize; ++i)
					{
						span<block> kk(kIter, kDepth + 1);
						span<block> g(kIter + kDepth + 1, groupSize);
						mk.setKey(i, kk, g);

						//*shareIter = BgiPirServer::fullDomain(pirData, kk, g);
					//if (neq(kIter[keySize - 1], ZeroBlock))
					//{
					//    std::cout << IoStream::lock << "bIdx " << binIdx << " " << i << " key " << kIter[keySize - 1] << "   shareIdx=" << (shareIter - shares.begin()) << " pir["<< *idxIter <<"] " << pirData[*idxIter]<< std::endl << IoStream::unlock;
					//}
					//++shareIter;
						kIter += keySize;
						//++idxIter;
					}


					std::vector<block> expandedBits(mBinSize);
					auto numSteps = mBinSize / 8;
					while (cuckooIdx < cuckooEnd)
					{


						{

							// for this bin and this slot, get all of the DPF values corresponding to it. 
							// One for each of the queries to this bin.
							auto bits = mk.yeild();
							auto bitsIter = bits.data();
							auto expandedBitsIter = expandedBits.data();
							for (u64 j = 0; j < numSteps; ++j)
							{
								expandedBitsIter[0] = zeroAndAllOne[bitsIter[0]];
								expandedBitsIter[1] = zeroAndAllOne[bitsIter[1]];
								expandedBitsIter[2] = zeroAndAllOne[bitsIter[2]];
								expandedBitsIter[3] = zeroAndAllOne[bitsIter[3]];
								expandedBitsIter[4] = zeroAndAllOne[bitsIter[4]];
								expandedBitsIter[5] = zeroAndAllOne[bitsIter[5]];
								expandedBitsIter[6] = zeroAndAllOne[bitsIter[6]];
								expandedBitsIter[7] = zeroAndAllOne[bitsIter[7]];
								expandedBitsIter += 8;
								bitsIter += 8;
							}
							for (u64 j = 0; j < mBinSize % 8; ++j)
							{
								expandedBitsIter[j] = zeroAndAllOne[bitsIter[j]];
							}
						}

						
						for (u64 i = 0; i < mBigBlockSize && cuckooIdx < cuckooEnd; ++i, ++cuckooIdx)
						{

							auto item = mIndex.mBins[cuckooIdx];
							auto empty = item.isEmpty();
							if (empty == false)
							{
								auto pirData_i = mCuckooData[cuckooIdx];

								//if (bits.size() != mBinSize) throw std::runtime_error(LOCATION);

								auto shareIter = shares.data() + binIdx * mBinSize * mBigBlockSize + i * mBinSize;
								auto expandedBitsIter = expandedBits.data();

								for (u64 j = 0; j < numSteps; ++j)
								{
									shareIter[0] = shareIter[0] ^ expandedBitsIter[0] & pirData_i;
									shareIter[1] = shareIter[1] ^ expandedBitsIter[1] & pirData_i;
									shareIter[2] = shareIter[2] ^ expandedBitsIter[2] & pirData_i;
									shareIter[3] = shareIter[3] ^ expandedBitsIter[3] & pirData_i;
									shareIter[4] = shareIter[4] ^ expandedBitsIter[4] & pirData_i;
									shareIter[5] = shareIter[5] ^ expandedBitsIter[5] & pirData_i;
									shareIter[6] = shareIter[6] ^ expandedBitsIter[6] & pirData_i;
									shareIter[7] = shareIter[7] ^ expandedBitsIter[7] & pirData_i;

									shareIter += 8;
									expandedBitsIter += 8;

									total += 8;
								}
								 
								for (u64 j = 0; j < mBinSize % 8; ++j)
								{
									shareIter[j] = shareIter[j] ^ expandedBitsIter[j] & pirData_i;

									++total;
								}


								//{
								//    auto hash = mIndex.mHashes[idx];
								//    std::cout << IoStream::lock << "sinput[" << idx << "] = " << mInputs[idx] << " -> pir["<< i << "], hash= "  << hash << " ("
								//        << CuckooIndex<>::getHash(hash, 0, mIndex.mBins.size()) << ", "
								//        << CuckooIndex<>::getHash(hash, 1, mIndex.mBins.size()) << ", "
								//        << CuckooIndex<>::getHash(hash, 2, mIndex.mBins.size()) << ") " << mIndex.mBins[cuckooIdx].hashIdx()
								//        << std::endl << IoStream::unlock;
								//}
							}
						}

					}

				}
				else
				{
					auto kIter = k.data() + keySize * binIdx * mBinSize;
					//vector<block>  pirData(&mCuckooData[cuckooIdx], cuckooEnd - cuckooIdx); 
					std::vector<block> pirData((u64(1) << kDepth) * groupSize * 128);

					//auto idxIter = idxs.data() + binIdx * mBinSize;
					auto shareIter = shares.begin() + binIdx * mBinSize;

					if ((cuckooEnd - cuckooIdx) > pirData.size())
					{
						throw std::runtime_error(LOCATION);
					}

					memcpy(pirData.data(), &mCuckooData[cuckooIdx], (cuckooEnd - cuckooIdx) * sizeof(block));
					//for (u64 i = 0; cuckooIdx < cuckooEnd; ++i, ++cuckooIdx)
					//{
					//	auto& item = mIndex.mBins[cuckooIdx];
					//	auto empty = item.isEmpty();
					//	if (empty == false)
					//	{
					//		auto idx = item.idx();
					//		pirData[i] = mCuckooData[cuckooIdx];

					//		//{
					//		//    auto hash = mIndex.mHashes[idx];
					//		//    std::cout << IoStream::lock << "sinput[" << idx << "] = " << mInputs[idx] << " -> pir["<< i << "], hash= "  << hash << " ("
					//		//        << CuckooIndex<>::getHash(hash, 0, mIndex.mBins.size()) << ", "
					//		//        << CuckooIndex<>::getHash(hash, 1, mIndex.mBins.size()) << ", "
					//		//        << CuckooIndex<>::getHash(hash, 2, mIndex.mBins.size()) << ") " << mIndex.mBins[cuckooIdx].hashIdx()
					//		//        << std::endl << IoStream::unlock;
					//		//}
					//	}
					//}

					for (u64 i = 0; i < mBinSize; ++i)
					{

						span<block> kk(kIter, kDepth + 1);
						span<block> g(kIter + kDepth + 1, groupSize);

						if (mNiave)
						{
							*shareIter = BgiPirServer::fullDomainNaive(pirData, kk, g);
						}
						else
						{
							*shareIter = BgiPirServer::fullDomain(pirData, kk, g);
						}
						//if (neq(kIter[keySize - 1], ZeroBlock))
						//{
						//    std::cout << IoStream::lock << "bIdx " << binIdx << " " << i << " key " << kIter[keySize - 1] << "   shareIdx=" << (shareIter - shares.begin()) << " pir["<< *idxIter <<"] " << pirData[*idxIter]<< std::endl << IoStream::unlock;
						//}
						++shareIter;
						kIter += keySize;
						//++idxIter;
					}
				}
			}
			//if (mServerId == 0)
			//std::cout << total << std::endl;

		};
		if (mServerId == 0) gTimer.setTimePoint("Drrn_Srv.query");

		std::vector<std::thread> thrds(numThreads - 1);
		for (u64 i = 1; i < numThreads; ++i)
			thrds[i - 1] = std::thread([i, &routine]() { routine(i); });

		routine(0);

		for (u64 i = 1; i < numThreads; ++i)
			thrds[i - 1].join();

		if (mServerId == 0) gTimer.setTimePoint("Drrn_Srv.psi");

		if (mServerId)
		{


			auto piSIter = mPiS1.begin();
			for (u64 j = 0; piSIter != mPiS1.end(); ++piSIter, ++j)
			{
				shares[j] = shares[j] ^ *piSIter;
			}

			srvChl.asyncSend(std::move(shares));
			//srvChl.asyncSend(std::move(piS1));
		}
		else
		{
			std::vector<u32> pi0(shares.size());
			std::vector<block> piS0(shares.size()),  piSigmaR0(shares.size());
			clientChl.recv((u8*)pi0.data(), pi0.size() * sizeof(u32));
			clientChl.recv(piS0);
			gTimer.setTimePoint("Drrn_Srv.recv_client_perm");
			//srvChl.recv((u8*)pi1SigmaRS.data(), pi1SigmaRS.size() * sizeof(block));

			for (u64 i = 0; i < shares.size(); ++i)
			{
				//std::cout << "pi(r + s)[" << i << "]=" << pi1SigmaRS[pi0[i]] << std::endl;
				piSigmaR0[i] = mPi1SigmaRS[pi0[i]] ^ piS0[i];
			}

			// reuse the memory
			auto& piSigmaRV1 = mPi1SigmaRS;
			srvChl.recv(piSigmaRV1);
			//srvChl.recv(piS1);
			gTimer.setTimePoint("Drrn_Srv.recv_server_perm");
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
			mPsi.sendInput(shares, clientChl);
		}

		if (mServerId == 0) gTimer.setTimePoint("Drrn_Srv.send_done");

	}
}
