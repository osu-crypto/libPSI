#pragma once

/* The OT thread uses the Miracl library, which is not thread safe.
 * Thus all Miracl based code is contained in this one thread so as
 * to avoid locking issues etc.
 *
 * Thus this thread serves all base OTs to all other threads
 */

//#include "OT/Extention/Networking/Player.h"
#include "Crypto/PRNG.h"
#include "Common/BitVector.h"
#include "Network/Channel.h"
#include "Crypto/AES.h"
#include "BaseOT.h"
#include <vector>

#define BASE_OT_COUNT 128

namespace libPSI
{


	// currently always assumes Both, i.e. do 2 sets of OT symmetrically,
	// use bitwise & to check for role
	enum OTRole
	{
		Receiver = 0x01,
		Sender = 0x10,
		Both = 0x11
	};

	OTRole INV_ROLE(OTRole role);

	//const char* role_to_str(OTRole role);
	//void send_if_ot_sender( Channel& P, vector<ByteStream>& os, OTRole role);
	//void send_if_ot_receiver( Channel &P, vector<ByteStream>& os, OTRole role);

	class PvwBaseOT
	{
	public:
		BitVector receiver_inputs;
		std::array< std::array<block, 2>, BASE_OT_COUNT> sender_inputs;
		std::array<block, BASE_OT_COUNT> receiver_outputs;
		Channel& mChannel;

		PvwBaseOT(Channel& channel, OTRole role = Both)
			: mChannel(channel), 
			nOT(BASE_OT_COUNT),
			ot_length(BASE_OT_COUNT),
			mOTRole(role)
		{
			receiver_inputs.reset(nOT);
			//sender_inputs.resize(nOT, std::vector<block>(2));
			//receiver_outputs.resize(nOT);
			//mGSender.resize(nOT, std::vector<PRNG>(2));
			//mGReceiver.resize(nOT);

			//for (int i = 0; i < nOT; i++)
			//{

			//	sender_inputs[i][0] = BitVector(8 * AES_BLK_SIZE);
			//	sender_inputs[i][1] = BitVector(8 * AES_BLK_SIZE);
			//	receiver_outputs[i] = BitVector(8 * AES_BLK_SIZE);
			//}
		}

		int length() { return ot_length; }

		// do the OTs
		void exec_base(PRNG& prng);
		// use PRG to get the next ot_length bits
		//void extend_length();
		void check();
	private:
		int nOT, ot_length;
		OTRole mOTRole;

		bool is_sender() { return (bool)(mOTRole & Sender); }
		bool is_receiver() { return (bool)(mOTRole & Receiver); }
	};



}
