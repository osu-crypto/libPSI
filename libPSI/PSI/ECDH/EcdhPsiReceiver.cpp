#include "EcdhPsiReceiver.h"
#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/sha1.h"
#include "cryptoTools/Common/Log.h"

#include <unordered_map>

namespace osuCrypto
{

    EcdhPsiReceiver::EcdhPsiReceiver()
    {
    }


    EcdhPsiReceiver::~EcdhPsiReceiver()
    {
    }
    void EcdhPsiReceiver::init(u64 n, u64 secParam, block seed)
    {
        mN = n;
        mSecParam = secParam;
        mPrng.SetSeed(seed);
        mIntersection.clear();
    }


    void EcdhPsiReceiver::sendInput(
        span<block> inputs,
        span<Channel> chls)
    {
        std::vector<PRNG> thrdPrng(chls.size());
        for (u64 i = 0; i < thrdPrng.size(); i++)
            thrdPrng[i].SetSeed(mPrng.get<block>());


		std::vector<block> thrdPrngBlock(chls.size());
		std::vector<std::vector<u64>> localIntersections(chls.size() - 1);

		u64 maskSizeByte = (40 + log2(inputs.size()) + 7) / 8;

		auto curveParam = Curve25519;
        auto RcSeed = mPrng.get<block>();

		std::unordered_map<u32, block> mapXab;
		mapXab.reserve(inputs.size());

		auto routine = [&](u64 t)
		{
			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;


			auto& chl = chls[t];
			auto& prng = thrdPrng[t];
			u8 hashOut[SHA1::HashSize];

			EllipticCurve curve(curveParam, prng.get<block>());

			SHA1 inputHasher;
			EccNumber b(curve);
			EccPoint yb(curve), yba(curve), point(curve), xa(curve), xab(curve);
			 b.randomize(RcSeed);

			std::vector<u8> sendBuff(yb.sizeBytes() * subsetInputSize);
			auto sendIter = sendBuff.data();

			std::vector<u8> recvBuff(xa.sizeBytes() * subsetInputSize);
			std::vector<u8> recvBuff2(xab.sizeBytes() * subsetInputSize);

		//	std::cout << "send H(y)^b" << std::endl;

			//send H(y)^b
			for (u64 i = inputStartIdx; i < inputEndIdx; ++i)
			{

				inputHasher.Reset();
				inputHasher.Update(inputs[i]);
				inputHasher.Final(hashOut);

				point.randomize(toBlock(hashOut));
				//std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

				yb = (point * b);
	
#ifdef PRINT
				if (i == 0)
					std::cout << "yb[" << i << "] " << yb << std::endl;
#endif
				yb.toBytes(sendIter);
				sendIter += yb.sizeBytes();
			}
			chl.asyncSend(std::move(sendBuff));


			//recv H(x)^a
			//std::cout << "recv H(x)^a" << std::endl;

			chl.recv(recvBuff);
			if (recvBuff.size() != subsetInputSize * xa.sizeBytes())
			{
				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}
			auto recvIter = recvBuff.data();

			//compute H(x)^a^b as map
			//std::cout << "compute H(x)^a^b " << std::endl;

			for (u64 i = inputStartIdx; i < inputEndIdx;i++)
			{
				xa.fromBytes(recvIter); recvIter += xa.sizeBytes();
				xab = xa*b;
				
				u8* temp = new u8[xab.sizeBytes()];
				xab.toBytes(temp);
				auto idx = *(u32*)&toBlock(temp);

#ifdef PRINT
				if (i == 0)
				{
					std::cout << "xab[" << i << "] " << xab << std::endl;
					std::cout << "idx[" << i << "] " << toBlock(idx) << std::endl;
				}
#endif // PRINT

				

				std::cout << IoStream::lock;
				mapXab.insert({ idx,toBlock(temp) });
				std::cout << IoStream::unlock;
			}
		};


        std::vector<std::thread> thrds(chls.size());
        for (u64 i = 0; i < u64(chls.size()); ++i)
        {
            thrds[i] = std::thread([=] {
                routine(i);
            });
        }


		for (auto& thrd : thrds)
			thrd.join();

#if 1
		auto routine2 = [&](u64 t)
		{
			u64 inputStartIdx = inputs.size() * t / chls.size();
			u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
			u64 subsetInputSize = inputEndIdx - inputStartIdx;


			auto& chl = chls[t];


			std::vector<u8> recvBuff2(maskSizeByte * subsetInputSize);

			//recv H(y)^b^a
			chl.recv(recvBuff2);
			if (recvBuff2.size() != subsetInputSize * maskSizeByte)
			{
				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}
			auto recvIter2 = recvBuff2.data();

			for (u64 i = inputStartIdx; i < inputEndIdx; i++)
			{

				auto& idx_yba = *(u32*)(recvIter2);

#ifdef PRINT
				if (i == 0)
					std::cout << "idx_yba[" << i << "] " << toBlock(idx_yba) << std::endl;
#endif // PRINT

				auto id = mapXab.find(idx_yba);
				if (id != mapXab.end()) {

					//std::cout << "id->first[" << i << "] " << toBlock(id->first) << std::endl;

					if (memcmp(recvIter2, &id->second, maskSizeByte) == 0)
					{
						//std::cout << "intersection item----------" << i << std::endl;
						if (t == 0)
							mIntersection.emplace_back(i);
						else
							localIntersections[t - 1].emplace_back(i);
					}
				}
				recvIter2 += maskSizeByte;

			}
			//std::cout << "done" << std::endl;

		};


		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				routine2(i);
			});
		}

		for (auto& thrd : thrds)
			thrd.join();

		u64 extraSize = 0;

		for (u64 i = 0; i < thrds.size()-1; ++i)
			extraSize += localIntersections[i].size();

		mIntersection.reserve(mIntersection.size() + extraSize);
		for (u64 i = 0; i < thrds.size()-1; ++i)
		{
			mIntersection.insert(mIntersection.end(), localIntersections[i].begin(), localIntersections[i].end());
		}
#endif


    }

}