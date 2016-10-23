#pragma once 
#include "OT/NChooseOne/NcoOtExt.h"
#include "Common/BitVector.h"
#include "Common/MatrixView.h"
#include "OT/Base/naor-pinkas.h"

#include "Network/Channel.h"

#include <array>
#include <vector>
#ifdef GetMessage
#undef GetMessage
#endif


namespace osuCrypto {

	class KkrtNcoOtSender : public NcoOtExtSender
	{
	public: 


		std::vector<PRNG> mGens;
		BitVector mBaseChoiceBits;
		std::vector<block> mChoiceBlks;

		bool hasBaseOts() const override
		{
			return mBaseChoiceBits.size() > 0;
		}

		void setBaseOts(
			ArrayView<block> baseRecvOts,
			const BitVector& choices) override;
		
		std::unique_ptr<NcoOtExtSender> split() override;


		void init(
			MatrixView<block> correlatedMsgs) override;


		void encode(
			const ArrayView<block> correlatedMgs,
			const ArrayView<block> codeWord,
			ArrayView<block> otCorrectionMessage,
			block& val) override;
	};
}

