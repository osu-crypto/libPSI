#include "OtBinMPsiSender.h"

#include "Crypto/Commit.h"
#include "Common/Log.h"
#include "Common/Timer.h"
#include "OT/Base/naor-pinkas.h"
#include "OT/TwoChooseOne/KosOtExtReceiver.h"
#include "OT/TwoChooseOne/KosOtExtSender.h"
namespace osuCrypto
{

	OtBinMPsiSender::OtBinMPsiSender()
	{
	}


	OtBinMPsiSender::~OtBinMPsiSender()
	{
	}

	void OtBinMPsiSender::init(u64 n, u64 statSec, u64 inputBitSize,
		Channel & chl0,
		NcoOtExtSender&  ots,
		NcoOtExtReceiver& otRecv,
		block seed)
	{
		init(n, statSec, inputBitSize, { &chl0 }, ots, otRecv, seed);
	}

	void OtBinMPsiSender::init(u64 n, u64 statSec, u64 inputBitSize,
		const std::vector<Channel*>& chls,
		NcoOtExtSender& otSend,
		NcoOtExtReceiver& otRecv,
		block seed)
	{
		mStatSecParam = statSec;
		mN = n;

		// must be a multiple of 128...
		u64 baseOtCount = 128 * CodeWordSize;

		mOtSend = &otSend;
		mOtRecv = &otRecv;

		//auto logn = std::log2(n);
		//mNumBins = (n + logn - 1) / logn;
		//mBinSize = logn * std::log2(logn);

		mPrng.SetSeed(seed);
		auto myHashSeed = mPrng.get<block>();
		auto& chl0 = *chls[0];


		Commit comm(myHashSeed), theirComm;
		chl0.asyncSend(comm.data(), comm.size());
		chl0.recv(theirComm.data(), theirComm.size());


		chl0.asyncSend(&myHashSeed, sizeof(block));
		block theirHashingSeed;
		chl0.recv(&theirHashingSeed, sizeof(block));

		mHashingSeed = myHashSeed ^ theirHashingSeed;



		mBins.init(n, inputBitSize, mHashingSeed, statSec);

		//mPsis.resize(mBins.mBinCount);

		u64 perBinOtCount = mBins.mMaxBinSize;// mPsis[0].PsiOTCount(mBins.mMaxBinSize, mBins.mRepSize);
		u64 otCount = perBinOtCount * mBins.mBinCount;


		if (otSend.hasBaseOts() == false)
		{
			// first do 128 public key OTs (expensive)
			std::array<std::array<block, 2>, gOtExtBaseOtCount> baseMsg;
			NaorPinkas base;
			base.send(baseMsg, mPrng, chl0, 2);

			// extend these using the malicious secure OT extension
			// protocol. This will give us ~800 2 choose 1 OTs.
			std::vector<block> recvBaseMsg(baseOtCount);
			BitVector recvChoice(baseOtCount); recvChoice.randomize(mPrng);
			KosOtExtReceiver kos;
			kos.setBaseOts(baseMsg);
			kos.receive(recvChoice, recvBaseMsg, mPrng, chl0);

			// now set these ~800 OTs as the base of our N choose 1 OTs.
			otSend.setBaseOts(recvBaseMsg, recvChoice);
		}

		if (otRecv.hasBaseOts() == false)
		{
			// first do 128 public key OTs (expensive)
			std::array<block, gOtExtBaseOtCount> baseMsg;
			BitVector choices(gOtExtBaseOtCount); choices.randomize(mPrng);
			NaorPinkas base;
			base.receive(choices, baseMsg, mPrng, chl0, 2);

			// extend these using the malicious secure OT extension
			// protocol. This will give us ~800 2 choose 1 OTs.
			std::vector<std::array<block, 2>> sendBaseMsg(baseOtCount);

			KosOtExtSender kos;
			kos.setBaseOts(baseMsg, choices);
			kos.send(sendBaseMsg, mPrng, chl0);

			// now set these ~800 OTs as the base of our N choose 1 OTs.
			otRecv.setBaseOts(sendBaseMsg);
		}




		mRecvOtMessages.resize(otCount* CodeWordSize);// = std::move(MatrixView<std::array<block, 2>>(otCount, CodeWordSize));
		mSendOtMessages.resize(otCount* CodeWordSize);// = std::move(MatrixView<block>(otCount, CodeWordSize));

		auto sendRoutine = [&](u64 i, u64 total, NcoOtExtSender& ots, Channel& chl)
		{
			// round up to the next 128 to make sure we aren't wasting OTs in the extension...
			u64 start = std::min(roundUpTo(i *     otCount / total, 128), otCount);
			u64 end = std::min(roundUpTo((i + 1) * otCount / total, 128), otCount);

			// get the range of rows starting at start and ending at end
			MatrixView<block> range(
				mSendOtMessages.begin() + (start * CodeWordSize),
				mSendOtMessages.begin() + (end *CodeWordSize),
				CodeWordSize);

			ots.init(range);
		};

		auto recvOtRountine = [&]
		(u64 i, u64 total, NcoOtExtReceiver& ots, Channel& chl)
		{
			u64 start = std::min(roundUpTo(i *     otCount / total, 128), otCount);
			u64 end = std::min(roundUpTo((i + 1) * otCount / total, 128), otCount);

			// get the range of rows starting at start and ending at end
			MatrixView<std::array<block, 2>> range(
				mRecvOtMessages.begin() + (start * CodeWordSize),
				mRecvOtMessages.begin() + (end *CodeWordSize),
				CodeWordSize);

			ots.init(range);
		};

		u64 numThreads = chls.size() - 1;
		u64 numSendThreads = numThreads / 2;
		u64 numRecvThreads = numThreads - numSendThreads;


		std::vector<std::unique_ptr<NcoOtExtSender>> sendOts(numSendThreads);
		std::vector<std::unique_ptr<NcoOtExtReceiver>> recvOts(numRecvThreads);
		std::vector<std::thread> thrds(numThreads);
		auto thrdIter = thrds.begin();
		auto chlIter = chls.begin() + 1;


		for (u64 i = 0; i < numSendThreads; ++i)
		{
			sendOts[i] = std::move(otSend.split());
			auto extSeed = mPrng.get<block>();

			*thrdIter++ = std::thread([&, i, extSeed, chlIter]()
			{
				//Log::out << Log::lock << "s sendOt " << i << "  " << (**chlIter).getName() << Log::endl << Log::unlock;
				sendRoutine(i + 1, numSendThreads + 1, *sendOts[i], **chlIter);
			});
			++chlIter;
		}

		for (u64 i = 0; i < numRecvThreads; ++i)
		{
			recvOts[i] = std::move(otRecv.split());
			auto extSeed = mPrng.get<block>();

			*thrdIter++ = std::thread([&, i, extSeed, chlIter]()
			{
				//Log::out << Log::lock << "s recvOt " << i << "  " << (**chlIter).getName() << Log::endl << Log::unlock;
				recvOtRountine(i, numRecvThreads, *recvOts[i], **chlIter);
			});
			++chlIter;
		}

		sendRoutine(0, numSendThreads + 1, otSend, chl0);

		if (numRecvThreads == 0)
		{
			recvOtRountine(0, 1, otRecv, chl0);
		}


		for (auto& thrd : thrds)
			thrd.join();
	}


	void OtBinMPsiSender::sendInput(std::vector<block>& inputs, Channel & chl)
	{
		sendInput(inputs, { &chl });
	}

	void OtBinMPsiSender::sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls)
	{
		if (inputs.size() != mN)
			throw std::runtime_error(LOCATION);



		TODO("actually compute the required mask size!!!!!!!!!!!!!!!!!!!!!!");
		u64 maskSize = 16;

		if (maskSize > sizeof(block))
			throw std::runtime_error("masked are stored in blocks, so they can exceed that size");


		std::vector<std::thread>  thrds(chls.size());
		//std::vector<std::thread>  thrds(1);		

		std::atomic<u32> remaining((u32)thrds.size()), remainingMasks((u32)thrds.size());
		std::promise<void> doneProm, maskProm;
		std::shared_future<void>
			doneFuture(doneProm.get_future()),
			maskFuture(maskProm.get_future());

		std::mutex mtx;

		std::array<std::vector<block>, CodeWordSize> codewordBuff;

		for (u64 hashIdx = 0; hashIdx < CodeWordSize; ++hashIdx)
			codewordBuff[hashIdx].resize(inputs.size());


		std::vector<u64> maskPermutation(mN*mBins.mMaxBinSize);
		for (u64 i = 0; i < maskPermutation.size(); ++i)
			maskPermutation[i] = i;
		std::random_shuffle(maskPermutation.begin(), maskPermutation.end(), mPrng);


		uPtr<Buff> sendMaskBuff(new Buff);
		sendMaskBuff->resize(maskPermutation.size() * maskSize);
		auto maskView = sendMaskBuff->getMatrixView<u8>(maskSize);

		for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
		{
			auto seed = mPrng.get<block>();
			thrds[tIdx] = std::thread([&, tIdx, seed]() {

				PRNG prng(seed);


				auto& chl = *chls[tIdx];
				auto startIdx = tIdx       * mN / thrds.size();
				auto endIdx = (tIdx + 1) * mN / thrds.size();

				// compute the region of inputs this thread should insert.
				//ArrayView<block> itemRange(
				//	inputs.begin() + startIdx,
				//	inputs.begin() + endIdx);

				std::array<AES, CodeWordSize> codewordHasher;
				for (u64 i = 0; i < codewordHasher.size(); ++i)
					codewordHasher[i].setKey(_mm_set1_epi64x(i) ^ mHashingSeed);


				for (u64 i = startIdx; i < endIdx; i += hasherStepSize)
				{
					auto currentStepSize = std::min(hasherStepSize, inputs.size() - i);

					for (u64 hashIdx = 0; hashIdx < CodeWordSize; ++hashIdx)
					{
						codewordHasher[hashIdx].ecbEncBlocks(
							inputs.data() + i,
							currentStepSize,
							codewordBuff[hashIdx].data() + i);
					}

					// since we are using random codes, lets just use the first part of the code 
					// as where each item should be hashed.
					for (u64 j = 0; j < currentStepSize; ++j)
					{
						block& item = codewordBuff[0][i + j];
						u64 addr = *(u64*)&item % mBins.mBinCount;

						std::lock_guard<std::mutex> lock(mBins.mMtx[addr]);
						mBins.mBins[addr].emplace_back(i + j);
					}
				}
				//<< Log::lock << "Sender"<< Log::endl;
				//mBins.insertItemsWithPhasing(range, mStatSecParam, inputs.size());


				// block until all items have been inserted. the last to finish will set the promise...
				if (--remaining)
					doneFuture.get();
				else
					doneProm.set_value();

				const u64 stepSize = 16;

				auto binStart = tIdx       * mBins.mBinCount / thrds.size();
				auto binEnd = (tIdx + 1) * mBins.mBinCount / thrds.size();

				auto otStart = binStart * mBins.mMaxBinSize;
				auto otEnd = binEnd * mBins.mMaxBinSize;


				Buff buff;


				MatrixView<block> correlatedSendOts(
					mSendOtMessages.begin() + (otStart * CodeWordSize),
					mSendOtMessages.begin() + (otEnd * CodeWordSize),
					CodeWordSize);
				u64 otIdx = 0;

				u64 maskIdx = otStart;

				for (u64 bIdx = binStart; bIdx < binEnd;)
				{

					u64 currentStepSize = std::min(stepSize, binEnd - bIdx);

					chl.recv(buff);
					if (buff.size() != CodeWordSize * sizeof(block) * mBins.mMaxBinSize * currentStepSize)
						throw std::runtime_error("not expected size");

					auto otCorrectionBuff = buff.getMatrixView<block>(CodeWordSize);
					//auto otCorrectionIter = otCorrectionBuff.begin();
					u64 otCorrectionIdx = 0;

					for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
					{
						auto& bin = mBins.mBins[bIdx];
						MultiBlock<CodeWordSize> codeword;

						for (auto inputIdx : bin)
						{
							u64 innerOtIdx = otIdx;
							u64 innerOtCorrectionIdx = otCorrectionIdx;

							for (u64 i = 0; i < mBins.mMaxBinSize; ++i)
							{
								for (u64 j = 0; j < CodeWordSize; ++j)
								{
									codeword[j] = codewordBuff[j][inputIdx];
								}

								block maskBlk;

								auto otMsg = correlatedSendOts[innerOtIdx];
								auto correction = otCorrectionBuff[innerOtCorrectionIdx];

								mOtSend->encode(
									otMsg,
									codeword,
									correction,
									maskBlk);


								TODO("add recv mask into this");

								// truncate the block size mask down to "maskSize" bytes
								// and store it in the maskView matrix at row maskIdx
								memcpy(
									maskView[maskPermutation[maskIdx]].data(),
									(u8*)&maskBlk,
									maskSize);


								++maskIdx;
								++innerOtIdx;
								++innerOtCorrectionIdx;
							}
						}

						otIdx += mBins.mMaxBinSize;
						otCorrectionIdx += mBins.mMaxBinSize;
					}

				}

				// block until all masks are computed. the last to finish will set the promise...
				if (--remainingMasks)
				{
					maskFuture.get();
				}
				else
				{
					maskProm.set_value();
				}

				if (tIdx == 0)
					chl.asyncSend(std::move(sendMaskBuff));




			});
		}

		for (auto& thrd : thrds)
			thrd.join();



	}

}


