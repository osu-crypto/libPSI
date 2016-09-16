#pragma once
#include "OT/OTExtInterface.h"
#ifdef GetMessage
#undef GetMessage
#endif

#include "Common/Defines.h"
#include <unordered_map> 
#include "Crypto/PRNG.h"

using namespace libPSI;


class OTOracleSender :
	public OtExtSender
{
public:
	OTOracleSender(const block& seed);
	~OTOracleSender();
	PRNG mPrng;
	bool hasBaseOts() const override { return true; }

	void setBaseOts(
		ArrayView<block> baseRecvOts,
		const BitVector& choices) override {};

	std::unique_ptr<OtExtSender> split() override
	{
		std::unique_ptr<OtExtSender> ret(new OTOracleSender(mPrng.get_block()));
		return std::move(ret);
	}

	void send(
		ArrayView<std::array<block,2>> messages,
		PRNG& prng,
		Channel& chl) override;
};
