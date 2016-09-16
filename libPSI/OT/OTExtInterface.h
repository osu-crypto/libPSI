#pragma once
#include "Common/ArrayView.h"
#include <array>
#ifdef GetMessage
#undef GetMessage
#endif


namespace libPSI
{
	class PRNG;
	class Channel;
	class BitVector;

	// The hard coded number of base OT that is expected by the OT Extension implementations.
	// This can be changed if the code is adequately adapted. 
	const u64 gOtExtBaseOtCount(128);
	
	class OtReceiver
	{
	public:
		OtReceiver() {}

		virtual void receive(
			const BitVector& choices,
			ArrayView<block> messages,
			PRNG& prng,
			Channel& chl) = 0;

	};

	class OtSender
	{
	public:
		OtSender() {}

		virtual void send(
			ArrayView<std::array<block, 2>> messages,
			PRNG& prng,
			Channel& chl) = 0;

	};

	class OtExtReceiver : public OtReceiver
	{
	public:
		OtExtReceiver() {}


		virtual void setBaseOts(
			ArrayView<std::array<block,2>> baseSendOts) = 0;

		virtual bool hasBaseOts() const = 0; 
		virtual std::unique_ptr<OtExtReceiver> split() = 0;
	};

	class OtExtSender : public OtSender
	{
	public:
		OtExtSender() {}

		virtual bool hasBaseOts() const = 0;

		virtual void setBaseOts(
			ArrayView<block> baseRecvOts,
			const BitVector& choices)  = 0;

		virtual std::unique_ptr<OtExtSender> split() = 0;
	};
}
