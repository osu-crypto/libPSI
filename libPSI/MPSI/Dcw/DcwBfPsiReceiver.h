#pragma once
#include "Common/Defines.h"
#include "Network/Channel.h"
#include "Crypto/sha1.h"
#include "Common/BitVector.h"
#include <vector>
#include "OT/TwoChooseOne/OTExtInterface.h"
namespace osuCrypto
{



	class DcwBfPsiReceiver
	{
	public:
	
		
		DcwBfPsiReceiver();
		~DcwBfPsiReceiver();

		//DcwOtReceiver mDcwOt;
		std::vector<SHA1> mHashs;
		u64 mMyInputSize, mTheirInputSize, mBfBitCount, mStatSecParam;
		block mHashingSeed;
		std::vector<u64> mIntersection;
		std::vector<block> mMessages;
		BitVector mRandChoices;
		block mEncSeed, mSeed;

		block interpolate(block prime, std::vector<block>& msgs, std::vector<u8>& choices);

		void init(u64 n, u64 statSecParam, OtExtReceiver& otExt, Channel& chl0, block seed);
		void init(u64 n, u64 statSecParam, OtExtReceiver& otExt, std::vector<Channel*>& chl0, block seed);
		void sendInput(std::vector<block>& inputs, Channel& chl);
		void sendInput(std::vector<block>& inputs, std::vector<Channel*>& chl0);
	};

}
