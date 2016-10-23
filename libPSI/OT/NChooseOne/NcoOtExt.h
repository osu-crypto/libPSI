#pragma once
#include "Common/MatrixView.h"
#include <array>
#ifdef GetMessage
#undef GetMessage
#endif


namespace osuCrypto
{
    class PRNG;
    class Channel;
    class BitVector;


    class NcoOtExtSender
    {
    public:

        virtual bool hasBaseOts() const = 0;

        virtual void setBaseOts(
            ArrayView<block> baseRecvOts,
            const BitVector& choices) = 0;
        
        virtual std::unique_ptr<NcoOtExtSender> split() = 0;

        virtual void init(
            MatrixView<block> correlatedMsgs) = 0;


        virtual void encode(
            const ArrayView<block> correlatedMgs,
            const ArrayView<block> codeWord,
            const ArrayView<block> otCorrectionMessage,
            block& val) = 0;
    };


    class NcoOtExtReceiver
    {
    public:

        virtual bool hasBaseOts() const = 0;

        virtual void setBaseOts(
            ArrayView<std::array<block, 2>> baseRecvOts) = 0;

        virtual std::unique_ptr<NcoOtExtReceiver> split() = 0;

        virtual void init(
            MatrixView<std::array<block, 2>> correlatedMsgs) = 0;


        virtual void encode(
            const ArrayView<std::array<block,2>> correlatedMgs,
            const ArrayView<block> codeWord,
            ArrayView<block> otCorrectionMessage,
            block& val) = 0;
    };

}
