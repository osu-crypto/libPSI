#include "KkrtPsiReceiver.h"
#include <future>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h"
#include "libPSI/TOols/SimpleHasher.h"
#include <libOTe/Base/naor-pinkas.h>
#include <unordered_map>

namespace osuCrypto
{


	std::string hexString(u8* data, u64 length)
	{
		std::stringstream ss;

		for (u64 i = 0; i < length; ++i)
		{

			ss << std::hex << std::setw(2) << std::setfill('0') << (u16)data[i];
		}

		return ss.str();
	}

	KkrtPsiReceiver::KkrtPsiReceiver()
	{
	}


	KkrtPsiReceiver::~KkrtPsiReceiver()
	{
	}

	void KkrtPsiReceiver::init(u64 senderSize, u64 recverSize, u64 statSecParam, Channel  chl0, NcoOtExtReceiver& ots, block seed)
	{
		std::array<Channel, 1> chans{ chl0 };
		init(senderSize, recverSize, statSecParam, chans , ots, seed);
	}


	void KkrtPsiReceiver::init(u64 senderSize, u64 recverSize, u64 statSecParam, ArrayView<Channel> chls, NcoOtExtReceiver& otRecv, block seed)
	{

		mStatSecParam = statSecParam;
		mSenderSize = senderSize;
		mRecverSize = recverSize;

		mIndex.init(recverSize, 40);

		//mNumStash = get_stash_size(recverSize);

		gTimer.setTimePoint("Init.start");
		PRNG prngHashing(seed);
		block myHashSeeds;
		myHashSeeds = prngHashing.get<block>();
		auto& chl0 = chls[0];


		// we need a random hash function, so both commit to a seed and then decommit later
		chl0.asyncSend(&myHashSeeds, sizeof(block));
		block theirHashingSeeds;
		chl0.asyncRecv(&theirHashingSeeds, sizeof(block));

		//gTimer.setTimePoint("Init.hashSeed");

		//do base OT
		if (otRecv.hasBaseOts() == false)
		{
			//Timer timer;
			gTimer.setTimePoint("Init: BaseSSOT start");



			//BaseSSOT baseSSOTs(chl0, OTRole::Sender);
			//baseSSOTs.exec_base(prngHashing);
			//baseSSOTs.check();
			//otRecv.setBaseSSOts(baseSSOTs.sender_inputs);
			gTimer.setTimePoint("Init: BaseSSOT done");
			//	Log::out << gTimer;
		}

		mHashingSeed = myHashSeeds ^ theirHashingSeeds;

		//gTimer.setTimePoint("Init.ExtStart");
		//extend OT
		otRecv.Extend(mBins.mBinCount + mNumStash, mSSOtMessages, chl0);

		//gTimer.setTimePoint("r Init.Done");
		//	Log::out << gTimer;
	}

	void KkrtPsiReceiver::sendInput(std::vector<block>& inputs, Channel & chl)
	{
		sendInput(inputs, { &chl });
	}

	struct has_const_member
	{
		const bool x;

		has_const_member(bool x_)
			: x(x_)
		{ }

	};

	void KkrtPsiReceiver::sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls)
	{




		//const bool leq1 = true;
		//define keysearch of mask based on mask length
//		typedef std::conditional<leq1, u32, u64>::type uMask;

		// check that the number of inputs is as expected.
		if (inputs.size() != mRecverSize)
			throw std::runtime_error("inputs.size() != mN");
		gTimer.setTimePoint("R Online.Start");

		//asign channel
		auto& chl = *chls[0];

		SHA1 sha1;
		u8 hashBuff[SHA1::HashSize];

		//random seed
		PRNG prng(_mm_set_epi32(42534612345, 34557734565, 211234435, 23987045));

		u64 codeWordSize = get_codeword_size(std::max<u64>(mSenderSize, mRecverSize)); //by byte
		u64 maskSize = get_mask_size(mSenderSize, mRecverSize); //by byte
		blockBop codeWord;

		//hash all items, use for: 1) arrage each item to bin using Cuckoo; 
		//                         2) use for psedo-codeword.
		std::array<AES, 4> AESHASH;
		TODO("make real keys seeds");
		for (u64 i = 0; i < AESHASH.size(); ++i)
			AESHASH[i].setKey(_mm_set1_epi64x(i));

		std::array<std::vector<block>, 4> aesHashBuffs;
		aesHashBuffs[0].resize(inputs.size());
		aesHashBuffs[1].resize(inputs.size());
		aesHashBuffs[2].resize(inputs.size());
		aesHashBuffs[3].resize(inputs.size());

		for (u64 i = 0; i < inputs.size(); i += stepSize)
		{
			auto currentStepSize = std::min(stepSize, inputs.size() - i);

			AESHASH[0].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[0].data() + i);
			AESHASH[1].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[1].data() + i);
			AESHASH[2].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[2].data() + i);
			AESHASH[3].ecbEncBlocks(inputs.data() + i, currentStepSize, aesHashBuffs[3].data() + i);
		};

		//insert item to corresponding bin
		mBins.insertItems(aesHashBuffs);
		//mBins.print();

		//we use 4 unordered_maps, we put the mask to the corresponding unordered_map 
		//that indicates of the hash function index 0,1,2. and the last unordered_maps is used for stash bin
		std::array<std::unordered_map<u64, std::pair<block, u64>>, 3> localMasks;
		//store the masks of elements that map to bin by h0
		localMasks[0].reserve(mBins.mBinCount); //upper bound of # mask
		//store the masks of elements that map to bin by h1
		localMasks[1].reserve(mBins.mBinCount);
		//store the masks of elements that map to bin by h2
		localMasks[2].reserve(mBins.mBinCount);

		std::unique_ptr<ByteStream> locaStashlMasks(new ByteStream());
		locaStashlMasks->resize(mNumStash* maskSize);


		//======================Bucket BINs (not stash)==========================

		//pipelining the execution of the online phase (i.e., OT correction step) into multiple batches
		TODO("run in parallel");
		auto binStart = 0;
		auto binEnd = mBins.mBinCount;
		gTimer.setTimePoint("R Online.computeBucketMask start");
		//for each batch
		for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
		{
			// compute the size of current step & end index.
			auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
			auto stepEnd = stepIdx + currentStepSize;

			// make a buffer for the pseudo-code we need to send
			std::unique_ptr<ByteStream> buff(new ByteStream());
			buff->resize((sizeof(blockBop)*currentStepSize));
			auto myOt = buff->getArrayView<blockBop>();

			// for each bin, do encoding
			for (u64 bIdx = stepIdx, i = 0; bIdx < stepEnd; bIdx++, ++i)
			{
				auto& item = mBins.mBins[bIdx];
				block mask(ZeroBlock);

				if (item.isEmpty() == false)
				{
					codeWord.elem[0] = aesHashBuffs[0][item.mIdx];
					codeWord.elem[1] = aesHashBuffs[1][item.mIdx];
					codeWord.elem[2] = aesHashBuffs[2][item.mIdx];
					codeWord.elem[3] = aesHashBuffs[3][item.mIdx];

					// encoding will send to the sender.
					myOt[i] =
						codeWord
						^ mSSOtMessages[bIdx][0]
						^ mSSOtMessages[bIdx][1];


					//compute my mask
					sha1.Reset();
					sha1.Update((u8*)&item.mHashIdx, sizeof(u64)); //
					sha1.Update((u8*)&mSSOtMessages[bIdx][0], codeWordSize);
					sha1.Final(hashBuff);


					// store the my mask value here					
					memcpy(&mask, hashBuff, maskSize);

					//store my mask into corresponding buff at the permuted position
					localMasks[item.mHashIdx].emplace(*(u64*)&mask, std::pair<block, u64>(mask, item.mIdx));

				}
				else
				{
					// no item for this bin, just use a dummy.
					myOt[i] = prng.get_block512(codeWordSize);
				}
			}
			// send the OT correction masks for the current step
			chl.asyncSend(std::move(buff));
		}// Done with compute the masks for the main set of bins. 		 
		gTimer.setTimePoint("R Online.sendBucketMask done");

		//receive the sender's marks, we have 3 buffs that corresponding to the mask of elements used hash index 0,1,2
		for (u64 buffIdx = 0; buffIdx < 3; buffIdx++)
		{
			ByteStream recvBuff;
			chl.recv(recvBuff);

			// double check the size. 
			if (recvBuff.size() != mSenderSize* maskSize)
			{
				Log::out << "recvBuff.size() != expectedSize" << Log::endl;
				throw std::runtime_error("rt error at " LOCATION);
			}

			auto theirMasks = recvBuff.data();

			//loop each mask
			if (maskSize >= 8)
			{
				//if masksize>=8, we can check 64 bits of key from the map first
				for (u64 i = 0; i < mSenderSize; ++i)
				{
					auto& msk = *(u64*)(theirMasks);

					// check 64 first bits
					auto match = localMasks[buffIdx].find(msk);

					//if match, check for whole bits
					if (match != localMasks[buffIdx].end())
					{
						if (memcmp(theirMasks, &match->second.first, maskSize) == 0) // check full mask
						{
							mIntersection.push_back(match->second.second);
							//Log::out << "#id: " << match->second.second << Log::endl;
						}
					}
					theirMasks += maskSize;
				}
			}
			else
			{
				for (u64 i = 0; i < mSenderSize; ++i)
				{
					for (auto match = localMasks[buffIdx].begin(); match != localMasks[buffIdx].end(); ++match)
					{
						if (memcmp(theirMasks, &match->second.first, maskSize) == 0) // check full mask
						{
							mIntersection.push_back(match->second.second);
							//Log::out << "#id: " << match->second.second << Log::endl;
						}
					}
					theirMasks += maskSize;
				}
			}
		}
		gTimer.setTimePoint("R Online.Bucket done");

		//======================STASH BIN==========================
		std::unique_ptr<ByteStream> stashBuff(new ByteStream());
		stashBuff->resize((sizeof(blockBop)*mBins.mStash.size()));
		auto myOt = stashBuff->getArrayView<blockBop>();

		gTimer.setTimePoint("R Online.Stash start");
		// compute the encoding for each item in the stash.
		for (u64 i = 0, otIdx = mBins.mBinCount; i < mBins.mStash.size(); ++i, ++otIdx)
		{
			auto& item = mBins.mStash[i];
			block mask(ZeroBlock);

			if (item.isEmpty() == false)
			{
				codeWord.elem[0] = aesHashBuffs[0][item.mIdx];
				codeWord.elem[1] = aesHashBuffs[1][item.mIdx];
				codeWord.elem[2] = aesHashBuffs[2][item.mIdx];
				codeWord.elem[3] = aesHashBuffs[3][item.mIdx];

				myOt[i] =
					codeWord
					^ mSSOtMessages[i][0]
					^ mSSOtMessages[i][1];

				sha1.Reset();
				sha1.Update((u8*)&mSSOtMessages[otIdx][0], codeWordSize);
				sha1.Final(hashBuff);
				
				memcpy(locaStashlMasks->data() + i * maskSize, hashBuff, maskSize);
			}
			else
			{
				myOt[i] = prng.get_block512(codeWordSize);
			}
		}

		chl.asyncSend(std::move(stashBuff));
		gTimer.setTimePoint("R Online.sendStashMask done");

		//receive masks from the stash
		for (u64 sBuffIdx = 0; sBuffIdx < mNumStash; sBuffIdx++)
		{
			ByteStream recvBuff;
			chl.recv(recvBuff);
			if (mBins.mStash[sBuffIdx].isEmpty()== false)
			{
				// double check the size.
				auto cntMask = mSenderSize;
				gTimer.setTimePoint("Online.MaskReceived from STASH");
				if (recvBuff.size() != cntMask* maskSize)
				{
					Log::out << "recvBuff.size() != expectedSize" << Log::endl;
					throw std::runtime_error("rt error at " LOCATION);
				}

				auto theirMasks = recvBuff.data();
					for (u64 i = 0; i < cntMask; ++i)
					{
						//check stash
							if (memcmp(theirMasks, locaStashlMasks->data()+ sBuffIdx*maskSize, maskSize) == 0) 
							{
								mIntersection.push_back(mBins.mStash[sBuffIdx].mIdx);
								//Log::out << "#id: " << match->second.second << Log::endl;
							}
						
						theirMasks += maskSize;
					}				
			}
		}

	gTimer.setTimePoint("Online.Done");
	//	Log::out << gTimer << Log::endl;
}
}