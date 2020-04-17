
#include "libPSI/config.h"
#ifdef ENABLE_KKRT_PSI
#include "KkrtPsiReceiver.h"
#include <future>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "libPSI/Tools/SimpleHasher.h"
#include <libOTe/Base/BaseOT.h>
#include <unordered_map>
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include <iomanip>
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
        init(senderSize, recverSize, statSecParam, chans, ots, seed);
    }


    void KkrtPsiReceiver::init(u64 senderSize, u64 recverSize, u64 statSecParam, span<Channel> chls, NcoOtExtReceiver& otRecv, block seed)
    {

        mStatSecParam = statSecParam;
        mSenderSize = senderSize;
        mRecverSize = recverSize;

        mIndex.init(recverSize, statSecParam, 0,3);

        //mNumStash = get_stash_size(recverSize);

        setTimePoint("kkrt.Recv.Init.start");
        PRNG prng(seed);
        block myHashSeeds;
        myHashSeeds = prng.get<block>();
        auto& chl0 = chls[0];


        //std::cout << IoStream::lock << "recv: sending PSI seed " << myHashSeeds << std::endl << IoStream::unlock;
        // we need a random hash function, so both commit to a seed and then decommit later
        chl0.asyncSend((u8*)&myHashSeeds, sizeof(block));
        block theirHashingSeeds;
        auto fu = chl0.asyncRecv((u8*)&theirHashingSeeds, sizeof(block));

        //setTimePoint("kkrt.Init.hashSeed");

        otRecv.configure(false, statSecParam, 128);

        //do base OT
        if (otRecv.hasBaseOts() == false)
        {
#if defined(LIBOTE_HAS_BASE_OT) && defined(ENABLE_IKNP)
            setTimePoint("kkrt.recv.Init: BaseSSOT start");
            DefaultBaseOT baseBase;
            std::array<block, 128> baseBaseOT;
            BitVector baseBaseChoice(128);
            baseBaseChoice.randomize(prng);
            baseBase.receive(baseBaseChoice, baseBaseOT, prng, chl0);

            IknpOtExtSender base;
            std::vector<std::array<block, 2>> baseOT(otRecv.getBaseOTCount());
            base.setBaseOts(baseBaseOT, baseBaseChoice, chl0);
            base.send(baseOT, prng, chl0);

            otRecv.setBaseOts(baseOT, prng, chl0);
            setTimePoint("kkrt.Kkrt PSI Init: BaseSSOT done");
#else
throw std::runtime_error("base OTs must be set or enable base OTs and IKNP in libOTe. " LOCATION);
#endif
        }

        fu.get();

        //std::cout << IoStream::lock << "recv: recved PSI seed " << theirHashingSeeds << std::endl << IoStream::unlock;

        mHashingSeed = myHashSeeds ^ theirHashingSeeds;

        otRecv.init(mIndex.mBins.size() + mIndex.mStash.size(), prng, chl0);
        mOtRecv = &otRecv;
    }

    void KkrtPsiReceiver::sendInput(span<block> inputs, Channel & chl)
    {
        std::array<Channel, 1> chls{ chl };
        sendInput(inputs,  chls );
    }

    void KkrtPsiReceiver::sendInput(span<block> inputs, span<Channel> chls)
    {
        // check that the number of inputs is as expected.
        if (inputs.size() != mRecverSize)
            throw std::runtime_error("inputs.size() != mN");
        setTimePoint("kkrt.R Online.Start");

        auto& chl = chls[0];

        //u64 codeWordSize = get_codeword_size(std::max<u64>(mSenderSize, mRecverSize)); //by byte
        u64 maskByteSize = static_cast<u64>(mStatSecParam + std::log2(mSenderSize * mRecverSize) + 7) / 8;//by byte

        //insert item to corresponding bin
        mIndex.insert(inputs, mHashingSeed);


        //we use 4 unordered_maps, we put the mask to the corresponding unordered_map
        //that indicates of the hash function index 0,1,2. and the last unordered_maps is used for stash bin
        std::array<std::unordered_map<u64, std::pair<block, u64>>, 3> localMasks;
        //store the masks of elements that map to bin by h0
        localMasks[0].reserve(mIndex.mBins.size()); //upper bound of # mask
        //store the masks of elements that map to bin by h1
        localMasks[1].reserve(mIndex.mBins.size());
        //store the masks of elements that map to bin by h2
        localMasks[2].reserve(mIndex.mBins.size());

        //std::unique_ptr<ByteStream> locaStashlMasks(new ByteStream());
        //locaStashlMasks->resize(mNumStash* maskSize);


        //======================Bucket BINs (not stash)==========================

        //pipelining the execution of the online phase (i.e., OT correction step) into multiple batches
        TODO("run in parallel");
        auto binStart = 0;
        auto binEnd = mIndex.mBins.size();
        setTimePoint("kkrt.R Online.computeBucketMask start");
        u64 stepSize = 1 << 10;

        //for each batch
        for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
        {
            // compute the size of current step & end index.
            auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
            auto stepEnd = stepIdx + currentStepSize;

            // for each bin, do encoding
            for (u64 bIdx = stepIdx, i = 0; bIdx < stepEnd; bIdx++, ++i)
            {
                //block mask(ZeroBlock);
                auto& bin = mIndex.mBins[bIdx];

                if (bin.isEmpty() == false)
                {
                    auto idx = bin.idx();

                    // get the smallest hash function index that maps this item to this bin.
                    auto hIdx = CuckooIndex<>::minCollidingHashIdx(bIdx,mIndex.mHashes[idx], 3, mIndex.mBins.size());

                    auto& item = inputs[idx];

                    block encoding = ZeroBlock;

                    mOtRecv->encode(bIdx, &item, &encoding, maskByteSize);

                    //std::cout << "r input[" << idx << "] = " << inputs[idx] << " h = " << (int)hIdx << " bIdx = " << bIdx << " -> " << *(u64*)&encoding << std::endl;

                    //store my mask into corresponding buff at the permuted position
                    localMasks[hIdx].emplace(*(u64*)&encoding, std::pair<block, u64>(encoding, idx));
                }
                else
                {
                    // no item for this bin, just use a dummy.
                    mOtRecv->zeroEncode(bIdx);
                }
            }
            // send the OT correction masks for the current step

            mOtRecv->sendCorrection(chl, currentStepSize);
        }// Done with compute the masks for the main set of bins.

        setTimePoint("kkrt.R Online.sendBucketMask done");


        //u64 sendCount = (mSenderSize + stepSize - 1) / stepSize;
        auto idxSize = std::min<u64>(maskByteSize, sizeof(u64));
        std::array<u64, 3> idxs{ 0,0,0 };


        auto numRegions = (mSenderSize  + stepSize -1) / stepSize;
        auto masksPerRegion = stepSize * 3;
        //std::this_thread::sleep_for(std::chrono::seconds(1));
        Matrix<u8> recvBuff(masksPerRegion, maskByteSize);
        //receive the sender's marks, we have 3 buffs that corresponding to the mask of elements used hash index 0,1,2
        for (u64 regionIdx = 0; regionIdx < numRegions; ++regionIdx)
        {
            auto start = regionIdx * stepSize;
            u64 curStepSize = std::min<u64>(mSenderSize - start, stepSize);
            auto end = start + curStepSize;

            chl.recv(recvBuff.data(), curStepSize * 3 * maskByteSize);

            std::array<u8*, 3>iters{
                recvBuff.data() + 0 * maskByteSize,
                recvBuff.data() + 1 * maskByteSize,
                recvBuff.data() + 2 * maskByteSize };

            for (u64 i = start; i < end; ++i)
            {

                memcpy(idxs.data() + 0, iters[0], idxSize);
                memcpy(idxs.data() + 1, iters[1], idxSize);
                memcpy(idxs.data() + 2, iters[2], idxSize);

                for (u64 k = 0; k < 3; ++k)
                {
                    auto iter = localMasks[k].find(idxs[k]);
                    //std::cout << " find(" << idxs[k] << ") = " << (iter != localMasks[k].end()) <<"   i " << i << " k " << k << std::endl;
                    if (iter != localMasks[k].end() && memcmp(&iter->second.first, iters[k], maskByteSize) == 0)
                    {
                        mIntersection.emplace_back(iter->second.second);
                        //break;
                    }
                }

                iters[0] += 3 * maskByteSize;
                iters[1] += 3 * maskByteSize;
                iters[2] += 3 * maskByteSize;
            }
        }
        setTimePoint("kkrt.R Online.Bucket done");

        //u8 dummy[1];
        //chl.recv(dummy, 1);
    }
}
#endif