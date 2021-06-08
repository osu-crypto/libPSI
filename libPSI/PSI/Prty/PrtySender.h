#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include "libPSI/config.h"
#ifdef ENABLE_PRTY_PSI

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"

#include "Poly/polyNTL.h"
#include "PrtyDefines.h"

#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ.h>
#include "Poly/polyFFT.h"
#include "Tools/SimpleIndex.h"

#include <array>
namespace osuCrypto {

	class PrtySender :public TimerAdapter
	{
	public:

		SimpleIndex simple;

		bool mHasBase;

		u64 mMyInputSize, mTheirInputSize, mPolyNumBytes, mPolyDegree, mStepSize, mPsiSecParam;
		std::vector<block> mS;
		KkrtNcoOtReceiver recvOprf;
		KkrtNcoOtSender sendOprf; //PQET
		
		u64 mFieldSize;
		ZZ mPrime;
		ZZ mPrimeLastSlice;



		block mTruncateBlk;


		PRNG mPrng;
		
		BitVector mOtChoices;
		std::vector<AES> mAesQ;

		u64 idxPermuteDoneforDebug, hashIdxforDebug;
		AES mAesHasher;

		std::array<block, numSuperBlocks > subRowQForDebug;
		

		void init(u64 myInputSize, u64 theirInputSize, u64 psiSecParam, PRNG& prng, span<Channel> chls);
		void output(span<block> inputs, span<Channel> chls);
		void outputBestComm(span<block> inputs, span<Channel> chls);
		void outputBigPoly(span<block> inputs, span<Channel> chls);
		
	
	};
}

#endif