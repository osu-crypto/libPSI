#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Network/Channel.h>
#include <libPSI/PSI/KkrtPsiSender.h>
#include <libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h>

namespace osuCrypto
{

    class DrrnPsiServer
    {
    public:

        void init(u8 serverId, Channel chan, Channel srvChl, u64 databaseSize, u64 clientSetSize, block seed);

        void send(Channel clientChl, Channel srvChl, span<block> inputs);

        CuckooIndex mIndex;
        KkrtNcoOtSender otSend;
        PRNG mPrng;
        KkrtPsiSender mPsi;

        u64 mClientSetSize, mServerSetSize;
        u8 mServerId;
        block mHashingSeed;
    };

}
