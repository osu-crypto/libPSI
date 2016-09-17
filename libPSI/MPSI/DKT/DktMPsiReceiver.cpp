#include "DktMPsiReceiver.h"
#include "Crypto/Curve.h"
#include "Crypto/sha1.h"
#include "Common/Log.h"

#include <unordered_map>
#include "Common/ByteStream.h"

namespace libPSI
{

	DktMPsiReceiver::DktMPsiReceiver()
	{
	}


	DktMPsiReceiver::~DktMPsiReceiver()
	{
	}
	void DktMPsiReceiver::init(u64 n, u64 secParam, block seed)
	{
		mN = n;
		mSecParam = secParam;
		mPrng.SetSeed(seed);
		mIntersection.clear();
	}


	void DktMPsiReceiver::sendInput(
		ArrayView<block> inputs,
		Channel& chl)
	{
		u8 hashOut[SHA1::HashSize];
		SHA1 sha;
		u64 theirInputSize = inputs.size();

		// curve must be prime order...
		EllipticCurve curve(Curve25519, mPrng.get_block());

		if (curve.getGenerators().size() < 3)
		{
			Log::out << ("DktMPsi require at least 3 generators") << Log::endl;
			throw std::runtime_error("DktMPsi require at least 3 generators");
		}

		const auto& g = curve.getGenerators()[0];
		const auto& gg = curve.getGenerators()[1];
		const auto& ggg = curve.getGenerators()[2];
		auto g2 = gg + ggg;

		typedef EccBrick BRICK;

		BRICK gBrick(g);
		BRICK ggBrick(gg);
		BRICK gggBrick(ggg);


		std::vector<EccPoint> inputPoints;
		inputPoints.reserve(inputs.size());

		EccPoint pch(curve);

		for (u64 i = 0; i < inputs.size(); ++i)
		{

			sha.Reset();
			sha.Update(inputs[i]);
			sha.Final(hashOut);

			inputPoints.emplace_back(curve);

			auto& point = inputPoints.back();

			PRNG prng(toBlock(hashOut));
			point.randomize(prng);

			//Log::out << "rp  " << point << "  " << toBlock(hashOut) << Log::endl;




			//ByteStream temp(point.sizeBytes());
			//point.toBytes(temp.data());
			//EccPoint tt(curve);
			//tt.fromBytes(temp.data());


			//Log::out << "p  " << point << Log::endl;
			//Log::out << "p' " << tt << Log::endl;
			//Log::out << point << Log::endl;

			if (i)
				pch = pch + point;
			else
				pch = point;
		}

		EccNumber Rc(curve);
		EccNumber sigmaD(curve);
		Rc.randomize(mPrng);
		sigmaD.randomize(mPrng);


		EccPoint X(curve), sigmaA(curve);
		auto gRc = gBrick * Rc;
		X = pch + gRc;

		//if (g * Rc != gRc)
		//{
		//	Log::out << "neq" << Log::endl;
		//}
		//Log::out << "g      " << g << Log::endl;
		//Log::out << "gRc    " << gRc << Log::endl;
		//Log::out << "gRc    " << g * Rc << Log::endl;
		//Log::out << "X      " << X << Log::endl;
		//Log::out << "X2     " << X2 << Log::endl;
		//Log::out << "pch    " << pch << Log::endl;
		//Log::out << "Rc     " << Rc << Log::endl;



		sigmaA = gBrick * sigmaD;
		sha.Reset();

		std::unique_ptr<ByteStream> sendBuff(new ByteStream(X.sizeBytes() * 2));
		auto iter = sendBuff->data();
		X.toBytes(iter); iter += X.sizeBytes();
		sigmaA.toBytes(iter);
		sha.Update(iter, sigmaA.sizeBytes());

		chl.asyncSend(std::move(sendBuff));


		std::vector<EccPoint> pchs, Ms, Ns, sigmaBs, sigma2As;
		pchs.reserve(inputs.size());
		Ms.reserve(inputs.size());
		Ns.reserve(inputs.size());
		sigmaBs.reserve(inputs.size());
		sigma2As.reserve(inputs.size());

		std::vector<EccNumber> Rcs, sigmaDs, sigmaPhis;
		Rcs.reserve(inputs.size());
		sigmaDs.reserve(inputs.size());
		sigmaPhis.reserve(inputs.size());


		const u64 stepSize = 64;


		for (u64 i = 0; i < inputs.size();)
		{
			auto curStepSize = std::min(stepSize, inputs.size() - i);


			sendBuff.reset(new ByteStream(g.sizeBytes() * 3 * curStepSize));
			auto iter = sendBuff->data();

			for (u64 j = 0; j < curStepSize; ++j, ++i)
			{
				sigmaDs.emplace_back(curve);
				sigmaBs.emplace_back(curve);
				pchs.emplace_back(curve);
				Rcs.emplace_back(curve);
				Ms.emplace_back(curve);
				Ns.emplace_back(curve);


				sigmaDs[i].randomize(mPrng);
				sigmaBs[i] = g2 * sigmaDs[i];

				pchs[i] = pch - inputPoints[i];

				Rcs[i].randomize(mPrng);
				auto grc = ggBrick * Rcs[i];
				Ms[i] = inputPoints[i] + grc;

				Ns[i] = pchs[i] + gggBrick  * Rcs[i];


				Ms[i].toBytes(iter); iter += Ms[i].sizeBytes();
				Ns[i].toBytes(iter); iter += Ns[i].sizeBytes();


				sigmaBs[i].toBytes(iter);
				sha.Update(iter, sigmaBs[i].sizeBytes());
				iter += Ns[i].sizeBytes();


			}
			chl.asyncSend(std::move(sendBuff));
		}

		EccNumber sigmaE(curve), sigmaPhi(curve);
		sha.Final(hashOut);
		PRNG ePrng(toBlock(hashOut));
		sigmaE.randomize(ePrng);

		sigmaPhi = sigmaD + Rc * sigmaE;
		//Log::out << Log::lock << "r e        " << sigmaE << Log::endl << Log::unlock;


		sendBuff.reset(new ByteStream(sigmaPhi.sizeBytes()));
		sigmaPhi.toBytes(sendBuff->data());
		chl.asyncSend(std::move(sendBuff));

		auto sigmaGZ = gBrick * sigmaPhi;

		EccNumber one(curve, 1);
		EccNumber zero(curve, 0);

		//Log::out << "r g^z      " << sigmaGZ << Log::endl;

		for (u64 i = 0; i < inputs.size();)
		{
			auto curStepSize = std::min(stepSize, inputs.size() - i);


			sendBuff.reset(new ByteStream(sigmaPhi.sizeBytes() * curStepSize));
			auto iter = sendBuff->data();

			for (u64 j = 0; j < curStepSize; ++j, ++i)
			{
				sigmaPhis.emplace_back(curve);
				sigmaPhis[i] = sigmaDs[i] + Rcs[i] * sigmaE;

				sigmaPhis[i].toBytes(iter); iter += sigmaPhis[i].sizeBytes();
				//Log::out << "X      " << X << Log::endl;
				//Log::out << "Ms[i]  " << Ms[i] << Log::endl;
				//Log::out << "Ns[i]  " << Ns[i] << Log::endl;

				auto XMN = (X - (Ms[i] + Ns[i]));

				
				//Log::out << "XMN    " << XMN << Log::endl;
				//Log::out << "sigmaE " << sigmaE << Log::endl;
				auto t = XMN * sigmaE;

				auto proof = (sigmaA - sigmaBs[i]) + t;
				auto checkVal = (g * sigmaPhi) - ((gg + ggg) * sigmaPhis[i]);

				if (checkVal != proof)
				{
					Log::out << "r expected " << checkVal << Log::endl;
					Log::out << "r actual   " << proof << Log::endl << Log::endl;
					// bad sigma proof
					throw std::runtime_error(LOCATION);
				}
			}

			chl.asyncSend(std::move(sendBuff));
		}

		EccPoint Z(curve), Mpi(curve), Kci(curve),  sigma2A(curve);
		EccNumber sigma2Phi(curve), sigma2C(curve);

		ByteStream buff;
		chl.recv(buff);
		if (buff.size() != sigma2A.sizeBytes()) throw std::runtime_error("");
		sigma2A.fromBytes(buff.data());
		sha.Reset();
		sha.Update(buff.data(), buff.size());

		for (u64 i = 0; i < inputs.size();)
		{
			auto curStepSize = std::min(stepSize, inputs.size() - i);

			chl.recv(buff);
			sha.Update(buff.data(), buff.size());

			auto expected = curStepSize * sigma2A.sizeBytes();
			if (buff.size() != expected)
				throw std::runtime_error(LOCATION);

			auto iter = buff.data();
			for (u64 j = 0; j < curStepSize; ++j, ++i)
			{
				sigma2As.emplace_back(curve);

				sigma2As.back().fromBytes(iter); iter += sigma2As.back().sizeBytes();
			}
		}


		sha.Final(hashOut);
		ePrng.SetSeed(toBlock(hashOut));
		sigma2C.randomize(ePrng);

		buff.resize(Z.sizeBytes() + sigma2Phi.sizeBytes());
		ByteStream buff2(Z.sizeBytes());

		chl.recv(buff.data(), buff.size());
		Z.fromBytes(buff.data());
		sigma2Phi.fromBytes(buff.data() + Z.sizeBytes());
		//EccBrick ZBrick(Z);

		auto sigma2ggPhiExpected = sigma2A + Z * sigma2C;
		auto sigma2ggPhi = gg * sigma2Phi;

		if (sigma2ggPhiExpected != sigma2ggPhi)
		{
			Log::out << "sender's sigma proof failed." << Log::endl;
			throw std::runtime_error("sender's sigma proof failed.");
		}


		struct InputHash
		{
			InputHash(block m, u64 i) : mHash(m), mInputIdx(i) {}
			block mHash;
			u64 mInputIdx;
		};
		std::unordered_map<u64, InputHash> hashs;

		//buff.resize(stepSize * Z.sizeBytes());

		for (u64 i = 0; i < inputs.size();)
		{
			auto curStepSize = std::min(stepSize, inputs.size() - i);

			chl.recv(buff);

			auto expected = curStepSize * Z.sizeBytes();
			if (buff.size() != expected)
				throw std::runtime_error(LOCATION);

			auto iter = buff.data();
			for (u64 j = 0; j < curStepSize; ++j, ++i)
			{

				Mpi.fromBytes(iter); iter += Mpi.sizeBytes();

				//EccPoint expectedMpi(curve);

				//expectedMpi = Ms[i] * Rs;

				auto negRcs = (zero - Rcs[i]);
				auto ZRcsi = Z * negRcs;
				Kci = ZRcsi + Mpi;
				//Log::out << "Kc[" << i << "] " << Kci << Log::endl;

				sha.Reset();
				Kci.toBytes(buff2.data());
				//Log::out << "buff " << buff << Log::endl;

				sha.Update(buff2.data(), Kci.sizeBytes());

				inputPoints[i].toBytes(buff2.data());
				sha.Update(buff2.data(), inputPoints[i].sizeBytes());

				sha.Update(inputs[i]);


				sha.Final(hashOut);

				auto blk = toBlock(hashOut);
				auto idx = *(u64*)&blk;
				//Log::out << "r " << blk << "  " << idx << Log::endl;
				hashs.insert({ idx , InputHash(blk, i) });



				auto sigma2MsiPhiExpected = sigma2As[i] + Mpi * sigma2C;
				auto sigma2MsiPhi = Ms[i] * sigma2Phi;

				if (sigma2MsiPhiExpected != sigma2MsiPhi)
				{
					Log::out << "sender's sigma proof failed (msi)." << Log::endl;
					throw std::runtime_error("sender's sigma proof failed (msi).");
				}

			}
		}


		for (u64 i = 0; i < theirInputSize; )
		{
			chl.recv(buff);
			auto view = buff.getArrayView<block>();
			i += view.size();

			for (auto& Tsj : view)
			{
				auto idx = *(u64*)&Tsj;
				//Log::out << "recv " << Tsj << Log::endl;
				//Log::out << "idx " << idx << Log::endl;
				auto iter = hashs.find(idx);


				if (iter != hashs.end())
				{
					//Log::out << "pm " << iter->second.mHash << "  " << iter->second.mInputIdx << Log::endl;

					if (eq(iter->second.mHash, Tsj))
					{
						mIntersection.emplace_back(iter->second.mInputIdx);
					}
				}

			}

			// termination condition is sending one extra byte
		}

	}
}