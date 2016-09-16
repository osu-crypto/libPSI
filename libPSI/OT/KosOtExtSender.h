#pragma once 
#include "OT/OTExtInterface.h"
#include "Common/BitVector.h"
#include "Crypto/PRNG.h"

#include <array>
namespace libPSI {

	class KosOtExtSender :
		public OtExtSender
	{
	public: 
		std::array<PRNG, gOtExtBaseOtCount> mGens;
		BitVector mBaseChoiceBits;

		bool hasBaseOts() const override
		{
			return mBaseChoiceBits.size() > 0;
		}

		std::unique_ptr<OtExtSender> split() override;

		void setBaseOts(
			ArrayView<block> baseRecvOts,
			const BitVector& choices) override;


		void send(
			ArrayView<std::array<block, 2>> messages,
			PRNG& prng,
			Channel& chl) override;
	};
}

