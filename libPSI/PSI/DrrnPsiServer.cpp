#include "DrrnPsiServer.h"
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <libPSI/PIR/BgiPirServer.h>
#include <libPSI/Tools/SimpleIndex.h>
namespace osuCrypto
{
    void DrrnPsiServer::init(u8 serverId, Channel clientChl, Channel srvChl, u64 databaseSize, u64 clientSetSize, block seed, double binScaler)
    {
        auto ssp(40);
        mPrng.SetSeed(seed);
        mIndex.init(databaseSize, ssp, true);
        mClientSetSize = clientSetSize;
        mServerSetSize = databaseSize;
        mHashingSeed = ZeroBlock; // todo, make random;
        mServerId = serverId;

        u64 numBalls = clientSetSize * mIndex.mParams.mNumHashes;
        mNumSimpleBins = (numBalls / std::log2(numBalls)) * binScaler;
        mBinSize = SimpleIndex::get_bin_size(mNumSimpleBins, numBalls, ssp);

        if (serverId == 0)
        {
            // i think these are the right set sizes for the final PSI        
            auto serverPsiInputSize = mBinSize * mNumSimpleBins;
            auto clientPsiInputSize = clientSetSize * mIndex.mParams.mNumHashes;
            mPsi.init(serverPsiInputSize, clientPsiInputSize, 40, clientChl, otSend, mPrng.get<block>());
        }
    }

    void DrrnPsiServer::send(Channel clientChl, Channel srvChl, span<block> inputs)
    {
        if (inputs.size() != mServerSetSize)
            throw std::runtime_error(LOCATION);

        mIndex.insert(inputs, mHashingSeed);

        u64 cuckooSlotsPerBin = (mIndex.mBins.size() + mNumSimpleBins) / mNumSimpleBins;


        // power of 2
        u64 numLeafBlocksPerBin = (cuckooSlotsPerBin + 127) / 128;
        u64 gDepth = 2;
        u64 kDepth = std::max<u64>(gDepth, log2floor(numLeafBlocksPerBin)) - gDepth;
        u64 groupSize = (numLeafBlocksPerBin + (1 << kDepth) - 1) / (1 << kDepth);
        if (groupSize > 8) throw     std::runtime_error(LOCATION);
        std::vector<block> pirData((1 << kDepth) * groupSize * 128);
        std::vector<block> shares(mNumSimpleBins * mBinSize);
        auto shareIter = shares.begin();

        u64 cuckooIdx = 0;
        for (u64 binIdx = 0; binIdx < mNumSimpleBins; ++binIdx)
        {
            auto curSize = std::min<u64>(cuckooSlotsPerBin, mIndex.mBins.size() - cuckooIdx);

            for (u64 i = 0; i < curSize; ++i, ++cuckooIdx)
            {
                if (mIndex.mBins[cuckooIdx].isEmpty() == false)
                {
                    auto idx = mIndex.mBins[cuckooIdx].idx();
                    pirData[i] = inputs[idx];

                    //auto hash = mIndex.mHashes[idx];

                    //std::cout << IoStream::lock << "sinput[" << idx << "] = " << inputs[i] << " -> " << hash << " ("
                    //    << CuckooIndex::getHash(hash, 0, mIndex.mBins.size()) << ", "
                    //    << CuckooIndex::getHash(hash, 1, mIndex.mBins.size()) << ", "
                    //    << CuckooIndex::getHash(hash, 2, mIndex.mBins.size()) << ") " << mIndex.mBins[cuckooIdx].hashIdx()
                    //    << std::endl << IoStream::unlock;
                }
            }



            std::vector<block> k(kDepth + 1 + groupSize);
            for (u64 i = 0; i < mBinSize; ++i)
            {
                clientChl.recv(k.data(), k.size() * sizeof(block));
                span<block> kk(k.data(), kDepth + 1);
                span<block> g(k.data() + kDepth + 1, groupSize);
                *shareIter = BgiPirServer::fullDomain(pirData, kk, g);
                ++shareIter;
                //if (mServerId) {
                //    u64 idx;
                //    clientChl.recv(&idx, sizeof(u64));
                //    block share;
                //    srvChl.recv(&share, sizeof(block));
                //    if (neq(share ^ shares[i], pirData[idx])) {
                //        std::cout << "failed at  " << i << "  " << idx << " " << (share ^ shares[i]) << " " << pirData[idx]<< std::endl;
                //    }
                //    else {
                //        std::cout << "passed at  " << i << "  " << idx << " " << share<<" ^ "<<shares[i] << " -> " << pirData[idx] << std::endl;
                //    }
                //}
                //else {
                //    srvChl.send(&shares[i], sizeof(block));
                //}


            }
        }

        if (mServerId)
        {
            block rSeed;
            clientChl.recv(&rSeed, sizeof(block));
            AES rGen(rSeed);


            std::array<block, 8> buff;
            u64 j = 0, end = shares.size() - 7;
            for (; j < end; j += 8)
            {
                rGen.ecbEncCounterMode(j, 8, buff.data());

                shares[j + 0] = shares[j + 0] ^ buff[0];
                shares[j + 1] = shares[j + 1] ^ buff[1];
                shares[j + 2] = shares[j + 2] ^ buff[2];
                shares[j + 3] = shares[j + 3] ^ buff[3];
                shares[j + 4] = shares[j + 4] ^ buff[4];
                shares[j + 5] = shares[j + 5] ^ buff[5];
                shares[j + 6] = shares[j + 6] ^ buff[6];
                shares[j + 7] = shares[j + 7] ^ buff[7];
            }
            rGen.ecbEncCounterMode(j, shares.size() - j, buff.data());
            for (u64 i = 0; j < shares.size(); ++j, ++i)
            {
                shares[j] = shares[j] ^ buff[i];
            }

            srvChl.asyncSend(std::move(shares));
        }
        else
        {

            std::vector<block> otherShare(shares.size());
            srvChl.recv(otherShare.data(), otherShare.size() * sizeof(block));

            u64  j = 0, end = shares.size() - 7;
            for (; j < end; j += 8)
            {
                shares[j + 0] = shares[j + 0] ^ otherShare[j + 0];
                shares[j + 1] = shares[j + 1] ^ otherShare[j + 1];
                shares[j + 2] = shares[j + 2] ^ otherShare[j + 2];
                shares[j + 3] = shares[j + 3] ^ otherShare[j + 3];
                shares[j + 4] = shares[j + 4] ^ otherShare[j + 4];
                shares[j + 5] = shares[j + 5] ^ otherShare[j + 5];
                shares[j + 6] = shares[j + 6] ^ otherShare[j + 6];
                shares[j + 7] = shares[j + 7] ^ otherShare[j + 7];
            }
            for (; j < shares.size(); ++j)
            {
                shares[j] = shares[j] ^ otherShare[j];
            }

            for (u64 i = 0; i < shares.size(); ++i)
            {
                std::cout << "sshare[" << i << "] = " << shares[i] << std::endl;
            }
            mPsi.sendInput(shares, clientChl);
        }
    }
}
