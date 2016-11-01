#pragma once
#include "OT/NChooseOne/NcoOtExt.h"
#include "Network/Channel.h"
#include <vector>

#ifdef GetMessage
#undef GetMessage
#endif

namespace osuCrypto
{

    class KkrtNcoOtReceiver : public NcoOtExtReceiver
    {
    public:


        KkrtNcoOtReceiver()
            :mHasBase(false)
        {}

        bool hasBaseOts()const override
        {
            return mHasBase;
        }

        bool mHasBase;
        std::vector<std::array<PRNG,2>> mGens;

        void setBaseOts(
            ArrayView<std::array<block, 2>> baseRecvOts) override;
        

        void init(
            MatrixView<std::array<block, 2>> correlatedMsgs) override;


        std::unique_ptr<NcoOtExtReceiver> split() override;

        void encode(
            const ArrayView<std::array<block, 2>> correlatedMgs,
            const ArrayView<block> codeWord,
            ArrayView<block> otCorrectionMessage,
            block& val) override;

        void getParams(
            u64 compSecParm, u64 statSecParam, u64 inputBitCount, u64 inputCount,
            u64& inputBlkSize, u64& baseOtCount) override;
    };

}
