#pragma once
#include "OT/OTExtInterface.h"
#include "Common/Defines.h"
#include <unordered_map> 

using namespace libPSI;

#ifdef GetMessage
#undef GetMessage
#endif

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

	void Extend(
		ArrayView<std::array<block,2>> messages,
		PRNG& prng,
		Channel& chl) override;
};
