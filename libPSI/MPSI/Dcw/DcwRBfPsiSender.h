#pragma once
#include "Common/Defines.h"
#include "Network/Channel.h"
#include "Crypto/sha1.h"
#include "OT/TwoChooseOne/OTExtInterface.h"

namespace osuCrypto {

	

	class DcwRBfPsiSender
	{
	public:
		DcwRBfPsiSender();
		~DcwRBfPsiSender();

		//void computeParameters(u64 n, u64 statSecParam, u64& totalOtCount, u64& cncOnesThreshold, double& cncProb, u64& numHashFunctions, u64& bfBitCount);

		u64 mN, mStatSecParam, mBfBitCount;
		//DcwOtSender mDcwOt;
		block mHashingSeed;
		std::vector<SHA1> mHashs;

		std::vector<std::array<block, 2>> mSendOtMessages;
		block computeSecureSharing(ArrayView<block> shares);
		block mEncSeed, mSeed;

		std::vector<block>mShares;
		block mSharesPrime;
		void init(u64 n, u64 statSecParam, OtExtSender& otExt, Channel& chl, block seed);
		void init(u64 n, u64 statSecParam, OtExtSender& otExt, std::vector<Channel*>& chl, block seed);


		void sendInput(std::vector<block>& inputs, Channel& chl);
		void sendInput(std::vector<block>& inputs, std::vector<Channel*>& chl);
	};

}
