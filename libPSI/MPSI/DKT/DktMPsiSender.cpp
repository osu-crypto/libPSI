#include "DktMPsiSender.h"
#include "Crypto/Curve.h"
#include "Crypto/sha1.h"
#include "Common/Log.h"

#include "Common/ByteStream.h"

namespace libPSI
{

	DktMPsiSender::DktMPsiSender()
	{
	}


	DktMPsiSender::~DktMPsiSender()
	{
	}
	void DktMPsiSender::init(u64 n, u64 secParam, block seed)
	{
		mN = n;
		mSecParam = secParam;
		mPrng.SetSeed(seed);
	}


	void DktMPsiSender::sendInput(std::vector<block>& inputs, Channel & chl)
	{
		u8 hashOut[SHA1::HashSize];
		SHA1 sha, sha2;

		// curve must be prime order...
		EllipticCurve curve(p224, mPrng.get_block());
		if (curve.getGenerators().size() < 3)
		{
			Log::out << ("DktMPsi require at least 3 generators") << Log::endl;
			throw std::runtime_error("DktMPsi require at least 3 generators");
		}

		u64 theirInputSize = inputs.size();

		const auto& g = curve.getGenerators()[0];
		const auto& gg = curve.getGenerators()[1];
		const auto& ggg = curve.getGenerators()[2];
		auto g2 = gg + ggg;


		typedef EccBrick BRICK;
		BRICK gBrick(g);
		//BRICK ggBrick(gg);
		//BRICK gggBrick(ggg);



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
			//Log::out << "sp  " << point << "  " << toBlock(hashOut) << Log::endl;

			if (i)
				pch = pch + point;
			else
				pch = point;
		}


		EccNumber Rs(curve);
		Rs.randomize(mPrng);


		//Log::out << " Rs " << Rs << Log::endl;
		EccNumber sigma2D(curve);
		EccPoint Z(curve), X(curve), sigmaA(curve), sigma2A(curve);
		Z = gg * Rs;

		//Log::out << "sZ  " << Z << Log::endl;

		Buff buff(X.sizeBytes() * 2);
		chl.recv(buff.data(), buff.size());
		X.fromBytes(buff.data());
		sigmaA.fromBytes(buff.data() + X.sizeBytes());

		sha.Reset();
		sha.Update(buff.data() + X.sizeBytes(), sigmaA.sizeBytes());

		std::vector<EccNumber> sigmaPhis;
		std::vector<EccPoint> Ms, Ns, Mps, sigmaBs, sigma2As;
		Ms.reserve(inputs.size());
		Ns.reserve(inputs.size());
		Mps.reserve(inputs.size());
		sigmaBs.reserve(inputs.size());
		sigmaPhis.reserve(inputs.size());
		sigma2As.reserve(inputs.size());

		buff.resize(X.sizeBytes() * 2);
		const u64 stepSize = 64;


		EccNumber sigma2R(curve);
		sigma2R.randomize(mPrng);

		sigma2A = gg * sigma2R;
		uPtr<Buff> sendBuff(new Buff(sigma2A.sizeBytes()));
		sigma2A.toBytes(sendBuff->data());
		
		sha2.Reset();
		sha2.Update(sendBuff->data(), sendBuff->size());

		chl.asyncSend(std::move(sendBuff));



		//EccPoint sigma2Ai(curve);
		for (u64 i = 0; i < theirInputSize;)
		{
			auto curStepSize = std::min(stepSize, inputs.size() - i);
			sendBuff.reset(new Buff(Z.sizeBytes() * curStepSize));

			chl.recv(buff);

			if (buff.size() != curStepSize * Z.sizeBytes() * 3)
				throw std::runtime_error(LOCATION);
			auto iter = buff.data();
			auto sendIter = sendBuff->data();
			
			for (u64 j = 0; j < curStepSize; ++j, ++i)
			{
				Ms.emplace_back(curve);
				Ns.emplace_back(curve);
				Mps.emplace_back(curve);
				sigmaBs.emplace_back(curve);

				Ms[i].fromBytes(iter); iter += Ms[i].sizeBytes();
				Ns[i].fromBytes(iter); iter += Ns[i].sizeBytes();
				sigmaBs[i].fromBytes(iter);

				sha.Update(iter, sigmaBs[i].sizeBytes());
				iter += sigmaBs[i].sizeBytes();


				Mps[i] = Ms[i] * Rs;

				sigma2As.emplace_back(curve);
				auto& sigma2Ai = sigma2As.back();
				sigma2Ai = Ms[i] * sigma2R;
				sigma2Ai.toBytes(sendIter); sendIter += sigma2Ai.sizeBytes();

			}

			sha2.Update(sendBuff->data(), sendBuff->size());
			chl.asyncSend(std::move(sendBuff));
			//Log::out << " buff  " << (u32)buff.data()[10] << Log::endl;
			//Log::out << " M[i]  " << Ms[i] << Log::endl;
			//Log::out << " Mp[i] " << Mps[i] << Log::endl;
			//Log::out << " Rs " << Rs << Log::endl;

			//Log::out << "mps"
		}

		EccNumber sigmaE(curve), sigmaPhi(curve), sigma2C(curve);
		sha2.Final(hashOut);
		PRNG ePrng(toBlock(hashOut));
		sigma2C.randomize(ePrng);

		auto sigma2Phi = sigma2R + sigma2C * Rs;




		sendBuff.reset(new Buff(Z.sizeBytes() + sigma2Phi.sizeBytes()));
		Z.toBytes(sendBuff->data());
		sigma2Phi.toBytes(sendBuff->data() + Z.sizeBytes());
		chl.asyncSend(std::move(sendBuff));

		sha.Final(hashOut);
		ePrng.SetSeed(toBlock(hashOut));
		sigmaE.randomize(ePrng);
		//Log::out << Log::lock << "s e        " << sigmaE << Log::endl << Log::unlock;
		

		chl.recv(buff);
		sigmaPhi.fromBytes(buff.data());

		auto sigmaGZ = gBrick * sigmaPhi;

		//Log::out << "s g^z      " << sigmaGZ << Log::endl;
		//EccNumber zero(curve, 0);


		for (u64 i = 0; i < theirInputSize;)
		{
			auto curStepSize = std::min(stepSize, inputs.size() - i);

			chl.recv(buff);

			if (buff.size() != curStepSize * sigmaPhi.sizeBytes())
				throw std::runtime_error(LOCATION);
			auto iter = buff.data();

			for (u64 j = 0; j < curStepSize; ++j, ++i)
			{
				sigmaPhis.emplace_back(curve);
				sigmaPhis[i].fromBytes(iter); iter += sigmaPhis[i].sizeBytes();

				//sigmaZs[i] = zero - sigmaZs[i];

				auto checkVal = sigmaGZ - (g2 * sigmaPhis[i]);
				auto proof = sigmaA - sigmaBs[i] + (X - (Ms[i] + Ns[i])) * sigmaE;


				if (checkVal != proof)
				{

					Log::out << "s sigmaPhis " << sigmaPhis[i] << Log::endl;
					Log::out << "s expected  " << checkVal << Log::endl;
					Log::out << "s actual    " << proof << Log::endl;
					// bad sigma proof
					//throw std::runtime_error(LOCATION);
				}
			}
		}


		for (u64 i = 0; i < Mps.size();)
		{

			auto curStepSize = std::min(stepSize, inputs.size() - i);
			sendBuff.reset(new Buff(Z.sizeBytes() * curStepSize));
			auto iter = sendBuff->data();


			for (u64 j = 0; j < curStepSize; ++j, ++i)
			{
				Mps[i].toBytes(iter); iter += Mps[i].sizeBytes();
			}

			chl.asyncSend(std::move(sendBuff));
		}



		EccPoint Ksj(curve);
		for (u64 i = 0; i < inputPoints.size();)
		{

			sendBuff.reset(new Buff(std::min(inputPoints.size() - i, u64(512)) * sizeof(block)));
			auto view = sendBuff->getArrayView<block>();

			for (u64 j = 0; j < view.size(); ++i, ++j)
			{

				Ksj = inputPoints[i] * Rs;
				//Log::out << "Ks[" << i << "] " << Ksj << Log::endl;

				sha.Reset();
				Ksj.toBytes(buff.data());
				sha.Update(buff.data(), Ksj.sizeBytes());

				inputPoints[i].toBytes(buff.data());
				sha.Update(buff.data(), inputPoints[i].sizeBytes());

				sha.Update(inputs[i]);

				sha.Final(hashOut);


				//Log::out << "s " << toBlock(hashOut) << Log::endl;

				view[j] = toBlock(hashOut);
			}

			chl.asyncSend(std::move(sendBuff));
		}



	}
}