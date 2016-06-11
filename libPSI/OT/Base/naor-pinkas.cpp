#include "naor-pinkas.h"
#include "Common/Log.h"
#include <memory>
#include "Common/Timer.h"

#define PARALLEL



namespace libPSI
{
#ifdef PARALLEL
	//static const  u64 minMsgPerThread(16);

	NaorPinkas::NaorPinkas()
	{

	}


	NaorPinkas::~NaorPinkas()
	{

	}


	void NaorPinkas::Receiver(ArrayView<block> messages, BitVector& choices, Channel& socket, PRNG& prng, u64 numThreads)
	{
		// should generalize to 1 out of N by changing this. But isn't tested...
		auto nSndVals(2);
		auto eccSecLevel = LT;

		//auto numThreads = (messages.size() + minMsgPerThread - 1) / minMsgPerThread;


		block seed = prng.get_block();
		std::unique_ptr<pk_crypto> mainPkGen(new ecc_field(eccSecLevel, (u8*)&seed));
		uint32_t fieldElementSize = mainPkGen->fe_byte_size();

		std::vector<std::thread> thrds(numThreads);
		std::unique_ptr<ByteStream> sendBuff(new ByteStream());
		sendBuff->resize(messages.size() * fieldElementSize);



		std::atomic<u32> remainingPK0s((u32)numThreads);
		std::promise<void>/* recvProm,*/ PK0Prom;
		//std::shared_future<void> recvFuture(recvProm.get_future());
		std::future<void> PK0Furture(PK0Prom.get_future());


		std::vector<u8> cBuff(nSndVals * fieldElementSize);
		auto cRecvFuture = socket.asyncRecv(cBuff.data(), cBuff.size()).share();


		for (u64 t = 0; t < numThreads; ++t)
		{
			//seed = prng.get_block();

			thrds[t] = std::thread(
				[t, numThreads, &messages, seed, eccSecLevel,
				&sendBuff, &choices, cRecvFuture, &cBuff,
				&remainingPK0s, &PK0Prom, nSndVals]()
			{

				auto mStart = t * messages.size() / numThreads;
				auto mEnd = (t + 1) * messages.size() / numThreads;

				std::unique_ptr<pk_crypto> thrdPkGen(new ecc_field(eccSecLevel, (u8*)&seed));
				//std::unique_ptr<pk_crypto>& thrdPkGen = mainPkGen;

				uint32_t fieldElementSize = thrdPkGen->fe_byte_size();

				std::unique_ptr<fe>
					PK0(thrdPkGen->get_fe()),
					g(thrdPkGen->get_generator());

				std::unique_ptr<brickexp>
					bg(thrdPkGen->get_brick(g.get()));

				std::vector<num*> pK(mEnd - mStart);
				std::vector<fe*> PK_sigma(mEnd - mStart),
					pC(nSndVals);


				for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
				{
					// get a random value from Z_p
					pK[j] = thrdPkGen->get_rnd_num();

					PK_sigma[j] = thrdPkGen->get_fe();

					// using brickexp which has the base of g, compute
					//
					//      PK_sigma[i] = g ^ pK[i]
					//
					// where pK[i] is just a random number in Z_p
					bg->pow(PK_sigma[j], pK[j]);
				}


				cRecvFuture.get();
				auto pBufIdx = cBuff.begin();

				for (auto u = 0; u < nSndVals; u++) {
					pC[u] = thrdPkGen->get_fe();
					pC[u]->import_from_bytes(&*pBufIdx);
					pBufIdx += fieldElementSize;
				}


				auto iter = sendBuff->data() + mStart * fieldElementSize;


				for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
				{
					u8 choice = choices[i];

					if (choice != 0) {
						PK0->set_div(pC[choice], PK_sigma[j]);
					}
					else {
						PK0->set(PK_sigma[j]);
					}
					PK0->export_to_bytes(iter);
					iter += fieldElementSize;

					//Log::out
					//	<< "for msg " << i << "  (recver)" << Log::endl
					//	<< "  PK0:        " << PK0->toString() << Log::endl
					//	<< "  PK_sigma:   " << PK_sigma[j]->toString() << Log::endl
					//	<< "  choice:     " << choice << Log::endl
					//	<< "  pC[choice]: " << pC[choice]->toString() << Log::endl;

				}

				//Log::out << *sendBuff << Log::endl;

				if (--remainingPK0s == 0)
					PK0Prom.set_value();

				//socket.asyncSend(std::move(sendBuff));



				//u8 shaBuff[SHA1::HashSize];

				ByteStream bs;
				bs.resize(SHA1::HashSize);

				// resuse this space, not the data of PK0...
				auto& gka = PK0;
				SHA1 sha;

				std::vector<u8>buff(fieldElementSize);
				std::unique_ptr<brickexp>bc(thrdPkGen->get_brick(pC[0]));

				for (u64 i = mStart, j = 0; i < mEnd; ++i, ++j)
				{
					// now compute g ^(a * k) = (g^a)^k 
					bc->pow(gka.get(), pK[j]);
					gka->export_to_bytes(buff.data());

					//Log::out
					//	<< "for msg " << i << ", " << choices[i] << "  (recver)" << Log::endl
					//	<< "  pDec[i]:    " << gka->toString() << Log::endl;

					sha.Reset();
					sha.Update((u8*)&i, sizeof(i));
					sha.Update(buff.data(), buff.size());
					sha.Final(bs.data());

					messages[i] = *(block*)bs.data();




					//Log::out
					//	<< "for msg " << i << ", " << choices[i] << "  (recver)" << Log::endl
					//	<< "  pDec[i]:    " << gka->toString() << Log::endl
					//	<< "  msg         " << messages[i]  << "  " << ByteStream(buff.data(), buff.size()) << "   " << bs << Log::endl;
				}


				for (auto ptr : pK)
					delete ptr;
				for (auto ptr : PK_sigma)
					delete ptr;
				for (auto ptr : pC)
					delete ptr;
			});
		}

		PK0Furture.get();

		socket.asyncSend(std::move(sendBuff));

		for (auto& thrd : thrds)
			thrd.join();

	}


	void NaorPinkas::Sender(ArrayView<std::array<block, 2>> messages, Channel& socket, PRNG & prng, u64 numThreads)
	{
		// one out of nSndVals OT.
		auto nSndVals(2);
		auto eccSecLevel = LT;

		//auto numThreads = (messages.size() + minMsgPerThread - 1) / minMsgPerThread;

		std::vector<std::thread> thrds(numThreads);



		auto seed = prng.get_block();
		std::unique_ptr<ecc_field> mainPk(new ecc_field(LT, (u8*)&seed));

		std::unique_ptr<num>
			alpha(mainPk->get_rnd_num()),
			PKr(mainPk->get_num()),
			tmp;

		std::unique_ptr<fe>
			g(mainPk->get_generator());

		uint32_t fieldElementSize = mainPk->fe_byte_size();


		std::unique_ptr<ByteStream> sendBuff(new ByteStream());
		sendBuff->resize(nSndVals * fieldElementSize);
		std::vector<fe*> pC(nSndVals);

		pC[0] = mainPk->get_fe();
		pC[0]->set_pow(g.get(), alpha.get());
		pC[0]->export_to_bytes(sendBuff->data());

		for (auto u = 1; u < nSndVals; u++)
		{
			pC[u] = mainPk->get_fe();
			tmp.reset(mainPk->get_rnd_num());
			pC[u]->set_pow(g.get(), tmp.get());

			pC[u]->export_to_bytes(sendBuff->data() + u * fieldElementSize);
		}

		socket.asyncSend(std::move(sendBuff));


		for (auto u = 1; u < nSndVals; u++)
			pC[u]->set_pow(pC[u], alpha.get());



		std::vector<u8> buff(fieldElementSize * messages.size());
		auto recvFuture = socket.asyncRecv(buff.data(), buff.size()).share();

		for (u64 t = 0; t < numThreads; ++t)
		{

			thrds[t] = std::thread([
				t, seed, fieldElementSize, &messages, recvFuture,
					numThreads, &buff, &alpha, nSndVals, &pC]()
			{

				std::unique_ptr<ecc_field> thrdPK(new ecc_field(LT, (u8*)&seed));

				std::unique_ptr<fe>
					pPK0(thrdPK->get_fe()),
					PK0a(thrdPK->get_fe()),
					fetmp(thrdPK->get_fe());

				std::vector<u8> hashInBuff(fieldElementSize);
				u8 shaBuff[SHA1::HashSize];
				SHA1 sha;


				auto mStart = t * messages.size() / numThreads;
				auto mEnd = (t + 1) * messages.size() / numThreads;

				recvFuture.get();

				for (u64 i = 0; i < messages.size(); i++)
				{

					pPK0->import_from_bytes(buff.data() + i * fieldElementSize);

					//Log::out
					//	<< "for msg " << i << "  (sender)" << Log::endl
					//	<< "  pPK0[i]:    " << pPK0->toString() << Log::endl;

					PK0a->set_pow(pPK0.get(), alpha.get());
					PK0a->export_to_bytes(hashInBuff.data());

					sha.Reset();
					sha.Update((u8*)&i, sizeof(i));
					sha.Update(hashInBuff.data(), hashInBuff.size());
					sha.Final(shaBuff);

					messages[i][0] = *(block*)shaBuff;

					//Log::out
					//	<< "for msg " << i << ", " << u << "  (sender)" << Log::endl
					//	<< "  PK0^a:    " << PK0a->toString() << Log::endl;

					for (u64 u = 1; u < nSndVals; u++)
					{

						fetmp->set_div(pC[u], PK0a.get());
						fetmp->export_to_bytes(hashInBuff.data());

						//Log::out
						//	<< "for msg " << i << ", " << u << "  (sender)" << Log::endl
						//	<< "  c^a/PK0^a:    " << fetmp->toString() << Log::endl;

						sha.Reset();
						sha.Update((u8*)&i, sizeof(i));
						sha.Update(hashInBuff.data(), hashInBuff.size());
						sha.Final(shaBuff);

						messages[i][u] = *(block*)shaBuff;
					}
				}
			});
		}


		for (auto& thrd : thrds)
			thrd.join();

		for (auto ptr : pC)
			delete ptr;
	}


#else

	void NaorPinkas::Receiver(ArrayView<block> messages, BitVector& choices, Channel& socket, PRNG & prng)
	{
		auto nSndVals(2);

		//Timer timer;
		//timer.setTimePoint("start");
		std::vector<fe*>
			PK_sigma(messages.size()),
			pC(nSndVals);

		std::vector<num*>
			pK(messages.size());

		auto seed = prng.get_block();
		std::unique_ptr<ecc_field> thrdPK(new ecc_field(LT, (u8*)&seed));

		std::unique_ptr<fe> PK0(thrdPK->get_fe()),
			g(thrdPK->get_generator());

		//Log::out << Log::lock << "recv g " << g->toString() << Log::endl << Log::unlock;

		uint32_t choice, fieldElementSize = thrdPK->fe_byte_size();
		std::unique_ptr<brickexp> bg(thrdPK->get_brick(g.get())), bc;

		for (u64 i = 0; i < messages.size(); i++)
		{
			// get a random value from Z_p
			pK[i] = thrdPK->get_rnd_num();

			PK_sigma[i] = thrdPK->get_fe();

			// using brickexp which has the base of g, compute
			//
			//      PK_sigma[i] = g ^ pK[i]
			//
			// where pK[i] is just a random number in Z_p
			bg->pow(PK_sigma[i], pK[i]);
		}

		std::vector<u8> buff(nSndVals * fieldElementSize);
		socket.recv(buff.data(), buff.size());
		auto pBufIdx = buff.begin();
		//timer.setTimePoint("recvInit");

		for (u64 u = 0; u < nSndVals; u++) {
			pC[u] = thrdPK->get_fe();
			pC[u]->import_from_bytes(&*pBufIdx);
			pBufIdx += fieldElementSize;
		}

		bc.reset(thrdPK->get_brick(pC[0]));



		std::unique_ptr<ByteStream> sendBuff(new ByteStream());
		sendBuff->resize(messages.size() * fieldElementSize);
		auto iter = sendBuff->data();

		for (u64 i = 0; i < messages.size(); i++)
		{
			choice = choices[((int32_t)i)];
			if (choice != 0) {
				PK0->set_div(pC[choice], PK_sigma[i]);
			}
			else {
				PK0->set(PK_sigma[i]);
			}
			PK0->export_to_bytes(iter);
			iter += fieldElementSize;

			//Log::out
			//	<< "for msg " << i << "  (recver)" << Log::endl
			//	<< "  PK0:        " << PK0->toString() << Log::endl
			//	<< "  PK_sigma:   " << PK_sigma[i]->toString() << Log::endl
			//	<< "  choice:     " << choices[i] << Log::endl
			//	<< "  pC[choice]: " << pC[choice]->toString() << Log::endl;

		}
		Log::out << *sendBuff << Log::endl;


		if (iter != sendBuff->data() + sendBuff->size())
			throw std::runtime_error(LOCATION);

		socket.asyncSend(std::move(sendBuff));
		//timer.setTimePoint("sent");

		buff.resize(fieldElementSize);
		//u8 shaBuff[SHA1::HashSize];

		ByteStream bs;
		bs.resize(SHA1::HashSize);
		//Log::out << Log::lock;

		// resuse this space, not the data of PK0...
		auto& gka = PK0;
		SHA1 sha;

		for (u64 i = 0; i < messages.size(); i++)
		{
			// now compute g ^(a * k) = (g^a)^k 
			bc->pow(gka.get(), pK[i]);
			gka->export_to_bytes(buff.data());


			sha.Reset();
			sha.Update((u8*)&i, sizeof(i));
			sha.Update(buff.data(), buff.size());
			sha.Final(bs.data());

			messages[i] = *(block*)bs.data();



			//Log::out
			//	<< "for msg " << i << ", " << choices[i] << "  (recver)" << Log::endl
			//	<< "  pDec[i]:    " << gka->toString() << Log::endl
			//	<< "  msg         " << messages[i] << "  " << ByteStream(buff.data(), buff.size()) << "   " << bs << Log::endl;
		}
		//Log::out << Log::unlock;
		//timer.setTimePoint("done");


		//Log::out << timer;
		for (auto ptr : PK_sigma)
			delete ptr;
		for (auto ptr : pC)
			delete ptr;
		for (auto ptr : pK)
			delete ptr;
	}


	void NaorPinkas::Sender(ArrayView<std::array<block, 2>> messages, Channel& socket, PRNG & prng)
	{
		// one out of nSndVals OT.
		auto nSndVals(2);



		auto seed = prng.get_block();
		std::unique_ptr<ecc_field> thrdPK(new ecc_field(LT, (u8*)&seed));

		std::unique_ptr<num>
			alpha(thrdPK->get_rnd_num()),
			PKr(thrdPK->get_num()),
			tmp;

		std::unique_ptr<fe>
			fetmp(thrdPK->get_fe()),
			PK0a(thrdPK->get_fe()),
			pPK0(thrdPK->get_fe()),
			g(thrdPK->get_generator());

		uint32_t fieldElementSize = thrdPK->fe_byte_size();


		std::unique_ptr<ByteStream> sendBuff(new ByteStream());
		sendBuff->resize(nSndVals * fieldElementSize);
		std::vector<fe*> pC(nSndVals);

		pC[0] = thrdPK->get_fe();
		pC[0]->set_pow(g.get(), alpha.get());
		pC[0]->export_to_bytes(sendBuff->data());

		for (auto u = 1; u < nSndVals; u++)
		{
			pC[u] = thrdPK->get_fe();
			tmp.reset(thrdPK->get_rnd_num());
			pC[u]->set_pow(g.get(), tmp.get());

			pC[u]->export_to_bytes(sendBuff->data() + u * fieldElementSize);
		}

		socket.asyncSend(std::move(sendBuff));


		for (auto u = 1; u < nSndVals; u++)
			pC[u]->set_pow(pC[u], alpha.get());



		std::vector<u8> buff(fieldElementSize * messages.size());
		socket.recv(buff.data(), buff.size());



		std::vector<u8> hashInBuff(fieldElementSize);
		u8 shaBuff[SHA1::HashSize];
		SHA1 sha;

		for (u64 i = 0; i < messages.size(); i++)
		{

			pPK0->import_from_bytes(buff.data() + i * fieldElementSize);

			//Log::out
			//	<< "for msg " << i << "  (sender)" << Log::endl
			//	<< "  pPK0[i]:    " << pPK0->toString() << Log::endl;

			PK0a->set_pow(pPK0.get(), alpha.get());
			PK0a->export_to_bytes(hashInBuff.data());

			sha.Reset();
			sha.Update((u8*)&i, sizeof(i));
			sha.Update(hashInBuff.data(), hashInBuff.size());
			sha.Final(shaBuff);

			messages[i][0] = *(block*)shaBuff;

			//Log::out
			//	<< "for msg " << i << ", " << u << "  (sender)" << Log::endl
			//	<< "  PK0^a:    " << PK0a->toString() << Log::endl;

			for (u64 u = 1; u < nSndVals; u++)
			{

				fetmp->set_div(pC[u], PK0a.get());
				fetmp->export_to_bytes(hashInBuff.data());

				//Log::out
				//	<< "for msg " << i << ", " << u << "  (sender)" << Log::endl
				//	<< "  c^a/PK0^a:    " << fetmp->toString() << Log::endl;

				sha.Reset();
				sha.Update((u8*)&i, sizeof(i));
				sha.Update(hashInBuff.data(), hashInBuff.size());
				sha.Final(shaBuff);

				messages[i][u] = *(block*)shaBuff;
			}
		}


		for (auto ptr : pC)
			delete ptr;
	}
#endif

}
