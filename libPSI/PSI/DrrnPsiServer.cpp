#include "DrrnPsiServer.h"
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <libPSI/PIR/BgiPirServer.h>
namespace osuCrypto
{
    void DrrnPsiServer::init(u8 serverId, Channel clientChl, Channel srvChl, u64 databaseSize, u64 clientSetSize, block seed)
    {
        mPrng.SetSeed(seed);
        mIndex.init(databaseSize, 40, true);
        mClientSetSize = clientSetSize;
        mServerSetSize = databaseSize;
        mHashingSeed = ZeroBlock; // todo, make random;
        mServerId = serverId;

        if (serverId == 0)
        {
            // i think these are the right set sizes for the final PSI
            auto serverPsiInputSize = clientSetSize * mIndex.mParams.mNumHashes;
            auto clientPsiInputSize = clientSetSize * mIndex.mParams.mNumHashes;
            mPsi.init(serverPsiInputSize, clientPsiInputSize, 40, clientChl, otSend, mPrng.get<block>());
        }
    }

    void DrrnPsiServer::send(Channel clientChl, Channel srvChl, span<block> inputs)
    {
        if (inputs.size() != mServerSetSize)
            throw std::runtime_error(LOCATION);

        mIndex.insert(inputs, mHashingSeed);

        // power of 2
        u64 numLeafBlocks = (mIndex.mParams.numBins() + 127) / 128;
        u64 gDepth = 2;
        u64 kDepth = log2floor(numLeafBlocks) - gDepth;
        u64 groupSize = (numLeafBlocks + (1 << kDepth)) / (1 << kDepth);
        if (groupSize > 8) throw     std::runtime_error(LOCATION);
        std::vector<block> pirData((1 << kDepth) * groupSize * 128);

        for (u64 i = 0; i < mIndex.mBins.size(); ++i)
        {
            if (mIndex.mBins[i].isEmpty() == false)
            {
                pirData[i] = inputs[mIndex.mBins[i].idx()];
                //if (mIndex.mBins[i].idx() < 1)
                //{
                //    std::cout << IoStream::lock << "pirData[" << i << "] = inputs[" << mIndex.mBins[i].idx() << "] = " << pirData[i] << " h=" << mIndex.mBins[i].hashIdx() << std::endl << IoStream::unlock;
                //}
            }
        }

        BgiPirServer pir;
        pir.init(kDepth, groupSize);

        std::vector<block> k(kDepth + 1 + groupSize);

        u64 numQueries = mClientSetSize * mIndex.mParams.mNumHashes;

        std::vector<block> shares(numQueries);
        for (u64 i = 0; i < numQueries; ++i)
        {
            clientChl.recv(k.data(), k.size() * sizeof(block));
            span<block> kk(k.data(), kDepth + 1);
            span<block> g(k.data() + kDepth + 1, groupSize);
            shares[i] = pir.fullDomain(pirData, kk, g);

            //if (mServerId)
            //{

            //    u64 idx;
            //    clientChl.recv(&idx, sizeof(u64));
            //    block share;
            //    srvChl.recv(&share, sizeof(block));

            //    if (neq(share ^ shares[i], pirData[idx]))
            //    {
            //        std::cout << "failed at  " << i << "  " << idx << " " << (share ^ shares[i]) << " " << pirData[idx]<< std::endl;
            //    }
            //    else
            //    {
            //        std::cout << "passed at  " << i << "  " << idx << " " << share<<" ^ "<<shares[i] << " -> " << pirData[idx] << std::endl;

            //    }
            //}
            //else
            //{
            //    srvChl.send(&shares[i], sizeof(block));
            //}


        }

        if (mServerId)
        {
            block rSeed;
            clientChl.recv(&rSeed, sizeof(block));
            AES rGen(rSeed);


            std::array<block, 8> buff;
            u64 j = 0, end = numQueries - 7;
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
            rGen.ecbEncCounterMode(j, numQueries - j, buff.data());
            for (u64 i =0; j < numQueries; ++j, ++i)
            {
                shares[j] = shares[j] ^ buff[i];
            }

            srvChl.asyncSend(std::move(shares));
        }
        else
        {

            std::vector<block> otherShare(numQueries);
            srvChl.recv(otherShare.data(), otherShare.size() * sizeof(block));

            u64  j = 0, end = numQueries - 7;
            for (;j < end;j += 8)
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
            for (;j < numQueries; ++j)
            {
                shares[j] = shares[j] ^ otherShare[j];
            }

            //for (u64 i = 0; i < shares.size(); ++i)
            //{
            //    std::cout << "sshare[" << i << "] = " << shares[i] << std::endl;
            //}
            mPsi.sendInput(shares, clientChl);
        }
    }
}
