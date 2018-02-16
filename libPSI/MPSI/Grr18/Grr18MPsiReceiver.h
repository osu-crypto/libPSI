#pragma once

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <libOTe/NChooseOne/NcoOtExt.h>
#include <libPSI/Tools/SimpleHasher.h>

namespace osuCrypto
{

    class Grr18MPsiReceiver
    {
    public:
        Grr18MPsiReceiver();
        ~Grr18MPsiReceiver();
        
        //static const u64 CodeWordSize = 7;
        //static const u64 hasherStepSize;

        bool mHashToSmallerDomain, mOneSided = true;
        double mEps = 0.1;
        u64 mN, mStatSecParam;// , mNumOTsUpperBound;// , mOtMsgBlkSize;
        block mHashingSeed;
        std::vector<u64> mIntersection;


        std::vector<std::unique_ptr<NcoOtExtSender>> mOtSends;
        std::vector<std::unique_ptr<NcoOtExtReceiver>> mOtRecvs;

        SimpleHasher mBins;
        PRNG mPrng;

        void init(u64 n, u64 statSecParam, Channel& chl0, NcoOtExtReceiver& otRecv, NcoOtExtSender& otSend, block seed,
            double binScaler = 1.0, u64 inputBitSize = -1);
        void init(u64 n, u64 statSecParam, span<Channel> chls, NcoOtExtReceiver& ots, NcoOtExtSender& otSend, block seed,
            double binScaler = 1.0, u64 inputBitSize = -1);

        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, span<Channel> chls);

    };




}
