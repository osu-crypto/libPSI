#include "DrrnPsiServer.h"
#include <libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h>
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
            KkrtNcoOtSender otSend;
            // i think these are the right set sizes for the final PSI
            auto serverPsiInputSize = clientSetSize * mIndex.mParams.mNumHashes;
            auto clientPsiInputSize = clientSetSize * mIndex.mParams.mNumHashes;
            mPsi.init(serverPsiInputSize, clientPsiInputSize, 40, clientChl, otSend, mPrng.get<block>());
        }
    }

    void DrrnPsiServer::send(Channel clientChl, Channel srvChl, span<block> inputs)
    {
        if (inputs.size() != mServerSetSize) throw std::runtime_error(LOCATION);

        mIndex.insert(inputs, mHashingSeed);


        // power of 2
        u64 depth = log2floor(mIndex.mParams.numBins() / 4);
        u64 treeLeaves = (1 << depth);
        u64 groupSize = (mIndex.mParams.numBins() + treeLeaves - 1) / treeLeaves;
        assert(groupSize <= 8);
        std::vector<block> pirData(treeLeaves * groupSize);


        for (u64 i = 0; i < mIndex.mBins.size(); ++i)
        {
            if (mIndex.mBins[i].isEmpty() == false)
            {
                pirData[i] = inputs[mIndex.mBins[i].idx()];
            }
        }

        BgiPirServer pir;
        pir.init(depth, groupSize);


        std::vector<block> k(depth + 1 + groupSize);

        u64 numQueries = mClientSetSize * mIndex.mParams.mNumHashes;

        std::vector<block> shares(numQueries);
        for (u64 i = 0; i < numQueries; ++i)
        {
            clientChl.recv(k.data(), k.size() * sizeof(block));

            span<block> kk(k.data(), depth + 1);
            span<block> g(k.data() + depth + 1, groupSize);
            shares[i] = pir.fullDomain(pirData, kk, g);
        }

        if (mServerId)
        {
            shares.resize(numQueries);
            block rSeed;
            clientChl.recv(&rSeed, sizeof(block));
            AES rGen(rSeed);
            for (u64 i = 0, j =0; i < numQueries / 8; ++i, j +=8)
            {
                std::array<block, 8> buff;
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

            srvChl.asyncSend(std::move(shares));
        }
        else
        {

            std::vector<block> otherShare(numQueries);
            srvChl.recv(otherShare.data(), otherShare.size() * sizeof(block));


            for (u64 i = 0, j = 0; i < numQueries / 8; ++i, j += 8)
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

            mPsi.sendInput(shares, clientChl);
        }

    }
}
