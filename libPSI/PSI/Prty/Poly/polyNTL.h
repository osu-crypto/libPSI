#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include "libPSI/config.h"
#ifdef ENABLE_PRTY_PSI

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>

#include "NTL/GF2EX.h"
#include "NTL/GF2XFactoring.h"
#include <NTL/GF2E.h>
#include "NTL/GF2EX.h"
#include <NTL/ZZ_pE.h>
#include <NTL/vec_ZZ_pE.h>
#include "NTL/GF2EX.h"
#include "NTL/ZZ_p.h"
#include "NTL/GF2EX.h" 
#include "NTL/GF2XFactoring.h"
#include "libPSI/PSI/Prty/PrtyDefines.h"

namespace osuCrypto
{

class polyNTL : public TimerAdapter
{
public:

	NTL::GF2X mGf2x;
	u64 mNumBytes;

	void NtlPolyInit(u64 numBytes);
	void GF2EFromBlock(NTL::GF2E &element, block& blk, u64 size);
	void GF2EFromBlocks(NTL::GF2E &element, block* blks, u64 size);

	void BlockFromGF2E(block& blk, NTL::GF2E & element, u64 size);

	void getBlkCoefficients(NTL::vec_GF2E& vecX, NTL::vec_GF2E& vecY, std::vector<block>& coeffs);
	void getBlkCoefficients(u64 degree, std::vector<block>& setX, std::vector<block>& setY, std::vector<block>& coeffs);
	void getSuperBlksCoefficients(u64 degree, std::vector<block>& setX
		, std::vector<std::array<block, numSuperBlocks>>& setY
		, std::vector<std::array<block, numSuperBlocks>>& coeffs);

	void evalPolynomial(std::vector<block>& coeffs, block& x, block& y);
	void evalPolynomial(std::vector<block>& coeffs, std::vector<block>& setX, std::vector<block>& setY);
	void evalPolynomial(std::vector<block>& coeffs, NTL::vec_GF2E& vecX, std::vector<block>& setY);
	void evalSuperPolynomial(std::vector<std::array<block, numSuperBlocks>>& coeffs
		, std::vector<block>& setX, std::vector<std::array<block, numSuperBlocks>>& setY);
};

}
#endif