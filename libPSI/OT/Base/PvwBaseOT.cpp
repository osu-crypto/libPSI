#include "OT/Base/PvwBaseOT.h"
#include "OT/Base/Math/DMC.h"
#include "Crypto/PRNG.h"
#include "Crypto/sha1.h"
#include "Network/Channel.h"
#include "cryptopp/osrng.h"
#include "Common/Log.h"

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <mutex>

//#include <boost/thread/tss.hpp>
//void Cleanup_Miracl(Miracl* miracl)
//{
//	if (miracl)
//	{
//		libPSI::Log::out << "deleting Miracle" << libPSI::Log::endl;
//		delete miracl;
//	}
//}


using namespace std;
namespace libPSI {

	const char* role_to_str(OTRole role)
	{
		if (role == Receiver)
			return "Receiver";
		if (role == Sender)
			return "Sender";
		return "Both";
	}

	OTRole INV_ROLE(OTRole role)
	{
		if (role == Receiver)
			return Sender;
		if (role == Sender)
			return Receiver;
		else
			return Both;
	}

	void send_if_ot_sender(Channel& channel, vector<ByteStream>& os, OTRole role)
	{

		if (role == Sender)
		{ 
			channel.asyncSendCopy(os[0].data(), os[0].size());
			//os[0].Send(channel);
		}
		else if (role == Receiver)
		{ 

			channel.recv(os[1]);
			//os[1].setp(0);
			//os[1].Receive(channel);
		}
		else
		{ 
			// both sender + receiver

			channel.asyncSendCopy(os[0]);
			channel.recv(os[1]);
			//os[0].Send(channel);
			//os[1].setp(0);
			//os[1].Receive(channel);
			//P->send_receive_player(os);
		}
	}

	void send_if_ot_receiver(Channel& channel, vector<ByteStream>& os, OTRole role)
	{
		if (role == Receiver)
		{ 
			channel.asyncSendCopy(os[0]);
		}
		else if (role == Sender)
		{ 
			channel.recv(os[1]);
			//P->receive(os[1]);
		}
		else
		{ 
			// both
			channel.asyncSendCopy(os[0]);
			channel.recv(os[1]);
			//P->send_receive_player(os);
		}
	}


	/*
	 * pack/unpack routines for Miracl data types
	 */

	void pack(ByteStream& s, const Big& z)
	{
		u8 data[50];
		i32 len = to_binary(z, 50, (char*)data, false);
		s.append((u8*)&len, sizeof(u32));
		s.append(data, len);
	}


	void unpack(Big& z, ByteStream& s)
	{
		u8 data[50];
		i32 len;
		s.consume((u8*)&len, sizeof(i32));
		s.consume(data, len);
		z = from_binary(len, (char*)data);
	}


	void pack(ByteStream& s, const ECn& P)
	{
		Big x, y;
		P.get(x, y);
		pack(s, x);
		pack(s, y);
	}


	void unpack(ECn& P, ByteStream& s)
	{
		Big x, y;
		unpack(x, s);
		unpack(y, s);
		P = ECn(x, y);
	}

	//#define BASEOT_DEBUG

		// Run the PVW OTs
	void Exec_OT(vector< vector<ECn> >& Miracl_Sender_Inputs,
		BitVector& OT_Receiver_Inputs,
		vector<ECn>& Miracl_Receiver_Outputs,
		const CRS& crs,
		csprng& Miracl_RNG,
		PRNG& G,
		Channel& channel,
		OTRole role)
	{
		u64 n = OT_Receiver_Inputs.size();
		//Log::out << Log::PvwBaseOT << "Starting base OTs as " << role_to_str(role) << ", n = " << n << Log::endl;
		vector<ByteStream> strm(2);

		Big z;
		vector<SK> sk(n);
		PK pk;
		if (role & Receiver)
		{
			// Generate my receiver inputs 
			OT_Receiver_Inputs.randomize(G);
			for (u64 i = 0; i < n; i++)
			{
				// Generate public keys on my branch
				KeyGen(sk[i], pk, OT_Receiver_Inputs[i], crs, Miracl_RNG);

				pack(strm[0], pk.g);
				pack(strm[0], pk.h);
			}
		}
		strm[1].setp(0);

		// Send receiver's public keys over
		send_if_ot_receiver(channel, strm, role);

		ECn c0, c1;

		if (role & Sender)
		{
			strm[0].setp(0);
			for (u64 i = 0; i < n; i++)
			{
				// Generate sender inputs
				z = strong_rand(&Miracl_RNG, crs.bit_size(), 2);
				Miracl_Sender_Inputs[i][0] = z*crs.get_g(0);
				z = strong_rand(&Miracl_RNG, crs.bit_size(), 2);
				Miracl_Sender_Inputs[i][1] = z*crs.get_g(0);

				// Unpack public keys, encrypt my two messages on the correct
				// branch and send them back
				unpack(pk.g, strm[1]);
				unpack(pk.h, strm[1]);

				pk.Encrypt(c0, c1, Miracl_Sender_Inputs[i][0], 0, crs, Miracl_RNG);
				pack(strm[0], c0);
				pack(strm[0], c1);
#ifdef BASEOT_DEBUG
				//Log::out << "m[" << i << ", 0] = " << Miracl_Sender_Inputs[i][0] << Log::endl;
				pack(strm[0], Miracl_Sender_Inputs[i][0]);
#endif
				pk.Encrypt(c0, c1, Miracl_Sender_Inputs[i][1], 1, crs, Miracl_RNG);
				pack(strm[0], c0);
				pack(strm[0], c1);
#ifdef BASEOT_DEBUG
				//Log::out << "m[" << i << ", 1] = " << Miracl_Sender_Inputs[i][1] << Log::endl;
				pack(strm[0], Miracl_Sender_Inputs[i][1]);
#endif
			}
		}

		// Sender sends ciphertexts over
		strm[1].setp(0);
		send_if_ot_sender(channel, strm, role); 

#ifdef BASEOT_DEBUG
		ECn m0, m1;
#endif

		if (role & Receiver)
		{
			// Now unpack the received ciphertexts, decrypt the one we want
			// and store it
			for (u64 i = 0; i < n; i++)
			{
				unpack(c0, strm[1]);
				unpack(c1, strm[1]);
#ifdef BASEOT_DEBUG
				unpack(m0, strm[1]);
#endif
				if (OT_Receiver_Inputs[i] == 0)
				{
					sk[i].Decrypt(Miracl_Receiver_Outputs[i], c0, c1);
#ifdef BASEOT_DEBUG
					if (Miracl_Receiver_Outputs[i] != m0)
					{
						Log::out << "Bad PvwBaseOT message received" << Log::endl;
						Log::out << "Received   " << Miracl_Receiver_Outputs[i] << Log::endl;
						Log::out << "wanted m0  " << m0 << Log::endl;
						throw std::runtime_error(LOCATION);
					}
#endif
				}
				unpack(c0, strm[1]);
				unpack(c1, strm[1]);
#ifdef BASEOT_DEBUG
				unpack(m1, strm[1]);
#endif
				if (OT_Receiver_Inputs[i] == 1)
				{
					sk[i].Decrypt(Miracl_Receiver_Outputs[i], c0, c1);
#ifdef BASEOT_DEBUG
					if (Miracl_Receiver_Outputs[i] != m1)
					{
						Log::out << "Bad PvwBaseOT message " << i << " received" << Log::endl;
						Log::out << "Received   " << Miracl_Receiver_Outputs[i] << Log::endl;
						Log::out << "wanted m1  " << m1 << Log::endl;
						throw std::runtime_error(LOCATION);
					}
#endif
				}




				//Log::out << Log::PvwBaseOT << "m"<< OT_Receiver_Inputs.get_bit(i) <<"[" << i << "] = " << Miracl_Receiver_Outputs[i] << Log::endl;

			}
		}
		//Log::out << Log::PvwBaseOT << "Exit base OT" << Log::endl;
	}


	void PvwBaseOT::exec_base(PRNG& G)
	{
		// Set up crs 
	  CRS crs(&(*GetPrecision()));
		//Log::out << "check 0" << Log::endl;

		// Initialize a secure random number generator for Miracl
		csprng Miracl_RNG;
		u8 data[100];
		//Log::out << "check 1" << Log::endl;
		G.get_u8s(data, 100);
		//CryptoPP::OS_GenerateRandomBlock(false, data, sizeof(u8) * 100);
 
		strong_init(&Miracl_RNG, 100, (char*)data, 0L);
		///Log::out << "check 2" << Log::endl;

		vector< vector<ECn> > Miracl_Sender_Inputs(nOT, vector<ECn>(2));
		vector<ECn>           Miracl_Receiver_Outputs(nOT);

		Exec_OT(Miracl_Sender_Inputs, receiver_inputs, Miracl_Receiver_Outputs, crs, Miracl_RNG, G, mChannel, mOTRole);

		ByteStream s;
		u8 buff[SHA1::HashSize];
		//CBC_MAC cbc;
		SHA1 sha;
		// Hash PVW output into byte strings
		for (int i = 0; i < nOT; i++)
		{
			if (mOTRole & Sender)
			{
				s.setp(0);
				pack(s, Miracl_Sender_Inputs[i][0]);

				sha.Reset();
				sha.Update(s.data(), s.size());
				sha.Final(buff);
				sender_inputs[i][0] = *(block*)buff;

				//cbc.zero_key();
				//cbc.Update(s);
				//cbc.Finalize(sender_inputs[i][0]);
#ifdef BASEOT_DEBUG
				s.setp(0);
				pack(s, Miracl_Sender_Inputs[i][0]);
				Log::out << Log::PvwBaseOT << "m[" << i << ", 0] s = " << s << Log::endl;
				mChannel.Send(s);
				s.setp(0);
				s.append(sender_inputs[i][0]);
				mChannel.AsyncSendCopy(s);
				Log::out << Log::PvwBaseOT << "m[" << i << ", 0]   = " << sender_inputs[i][0] << Log::endl;
#endif
				s.setp(0);
				pack(s, Miracl_Sender_Inputs[i][1]);
				sha.Reset();
				sha.Update(s.data(), s.size());
				sha.Final(buff);

				//cbc.zero_key();
				//cbc.Update(s); 
				//cbc.Finalize(sender_inputs[i][1]);
				sender_inputs[i][1] = *(block*)buff;
#ifdef BASEOT_DEBUG
				s.setp(0);
				pack(s, Miracl_Sender_Inputs[i][1]);
				mChannel.Send(s);
				Log::out << Log::PvwBaseOT << "m[" << i << ", 1] s = " << s << Log::endl;

				s.setp(0);
				s.append(sender_inputs[i][1]);
				mChannel.AsyncSendCopy(s);
				Log::out << Log::PvwBaseOT << "m[" << i << ", 1]   = " << sender_inputs[i][1] << Log::endl;
#endif
			}
			if (mOTRole & Receiver)
			{
				s.setp(0);
				pack(s, Miracl_Receiver_Outputs[i]);
				sha.Reset();
				sha.Update(s.data(), s.size());
				sha.Final(buff);

				receiver_outputs[i] = *(block*)buff;

				//cbc.zero_key();
				//cbc.Update(s);
				//cbc.Finalize(receiver_outputs[i]);

#ifdef BASEOT_DEBUG
				Log::out << Log::PvwBaseOT << "s " << s << Log::endl;
				ECn ecm0, ecm1;
				block m0, m1;

				s.setp(0);
				mChannel.recv(s);
				unpack(ecm0, s);
				s.setp(0);
				mChannel.recv(s);
				s.consume(m0);

				s.setp(0);
				mChannel.recv(s);
				unpack(ecm1, s);
				s.setp(0);
				mChannel.recv(s);
				s.consume(m1);

				if (receiver_inputs[i])
				{
					if (Miracl_Receiver_Outputs[i] != ecm1)
					{
						Log::out << "Bad PvwBaseOT Miracl message " << i << " received" << Log::endl;
						Log::out << "Received   " << Miracl_Receiver_Outputs[i] << Log::endl;
						Log::out << "wanted m1  " << ecm1 << Log::endl;
						throw std::runtime_error(LOCATION);
					}

					if (receiver_outputs[i] != m1)
					{
						Log::out << "Bad PvwBaseOT message " << i << " received" << Log::endl;
						Log::out << "Received   " << receiver_outputs[i] << Log::endl;
						Log::out << "wanted m1  " << m1 << Log::endl;
						throw std::runtime_error(LOCATION);
					}
				}
				else
				{

					if (Miracl_Receiver_Outputs[i] != ecm0)
					{
						Log::out << "Bad PvwBaseOT Miracl message " << i << " received" << Log::endl;
						Log::out << "Received   " << Miracl_Receiver_Outputs[i] << Log::endl;
						Log::out << "wanted m0  " << ecm0 << Log::endl;
						throw std::runtime_error(LOCATION);
					}

					if (receiver_outputs[i] != m0)
					{
						Log::out << "Bad PvwBaseOT message " << i << " received" << Log::endl;
						Log::out << "Received   " << receiver_outputs[i] << Log::endl;
						Log::out << "wanted m0  " << m0 << Log::endl;
						throw std::runtime_error(LOCATION);
					}
				}
#endif
			}

		}
		deletePercision();
		//delete GetPrecision();
		//Log::out << "base ots done" << Log::endl;
	}

	void PvwBaseOT::check()
	{
		ByteStream os;
		block tmp;

		for (int i = 0; i < nOT; i++)
		{
			if (mOTRole & Sender)
			{
				// send both inputs over
				os.append(sender_inputs[i][0]);
				os.append(sender_inputs[i][1]);

				if (eq(sender_inputs[i][0], sender_inputs[i][1]))
					throw std::runtime_error(LOCATION);


				mChannel.asyncSendCopy(os);
			}

			if (mOTRole & Receiver)
			{
				mChannel.recv(os);

				os.consume((u8*)&tmp, sizeof(block));

				if (receiver_inputs[i] == 1)
				{
					os.consume((u8*)&tmp, sizeof(block));
				}

				if (neq(tmp, receiver_outputs[i]))
				{
					Log::out << "Base Incorrect OT" << Log::endl;
					Log::out << "I        have " << receiver_outputs[i] << Log::endl;
					Log::out << "but they have " << tmp << Log::endl;

					throw std::runtime_error("Exit");;
				}
			}
			os.setp(0);
		}
	}

}
