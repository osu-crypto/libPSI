#pragma once
#include "Common/Defines.h"
#include "Network/Channel.h"
#include "OT/AknOtReceiver.h"


namespace libPSI
{

	void computeAknBfParams(u64 n, u64 statSecParam, u64& totalOtCount, u64& totalOnesCount, u64& cncOnesThreshold, double& cncProb, u64& numHashFunctions, u64& bfBitCount);


	class AknBfMPsiReceiver
	{
	public:
	
		
		AknBfMPsiReceiver();
		~AknBfMPsiReceiver();

		AknOtReceiver mAknOt;
		std::vector<SHA1> mHashs;
		u64 mMyInputSize, mTheirInputSize, mBfBitCount, mStatSecParam;
		block mHashingSeed, mSeed;
		std::vector<u64> mIntersection;

		void init(u64 n, u64 statSecParam, OtExtReceiver& otExt, Channel& chl0, block seed);
		void init(u64 n, u64 statSecParam, OtExtReceiver& otExt, std::vector<Channel*>& chl0, block seed);
		void sendInput(std::vector<block>& inputs, Channel& chl);
		void sendInput(std::vector<block>& inputs, std::vector<Channel*>& chl0);
	};

}
