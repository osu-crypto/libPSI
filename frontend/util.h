#pragma once
#include "cryptoTools/Network/BtChannel.h"

using namespace osuCrypto;

struct LaunchParams
{
    LaunchParams()
        :mVerbose(0),
        mTrials(1),
        mStatSecParam(40)
    {
    }

    std::vector<Channel*> getChannels(u64 n)
    {
        return  std::vector<Channel*>( mChls.begin(), mChls.begin() + n);
    }

    std::string mHostName;
    std::vector<Channel*> mChls;
    std::vector<u64> mNumItems;
    std::vector<u64> mNumThreads;

    u64 mVerbose;
    u64 mTrials;
    u64 mStatSecParam;
};


#include "cryptoTools/Network/Channel.h"
void senderGetLatency(osuCrypto::Channel& chl);

void recverGetLatency(osuCrypto::Channel& chl);
