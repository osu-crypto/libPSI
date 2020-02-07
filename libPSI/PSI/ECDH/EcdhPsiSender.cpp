#include "EcdhPsiSender.h"
#ifdef ENABLE_ECDH_PSI

#ifndef ENABLE_RELIC
#pragma error("ENABLE_RELIC must be defined in libOTe")
#endif

#include "cryptoTools/Crypto/Curve.h"
#include "cryptoTools/Crypto/RCurve.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Network/Channel.h"


namespace osuCrypto
{


    EcdhPsiSender::EcdhPsiSender()
    {
    }


    EcdhPsiSender::~EcdhPsiSender()
    {
    }
    void EcdhPsiSender::init(u64 n, u64 secParam, block seed)
    {
        mN = n;
        mSecParam = secParam;
        mPrng.SetSeed(seed);
    }


    void EcdhPsiSender::sendInput(std::vector<block>& inputs, span<Channel> chls)
    {


        u64 theirInputSize = inputs.size();

		u64 maskSizeByte = (40 + 2*log2(inputs.size())+7) / 8;

        std::vector<PRNG> thrdPrng(chls.size());
        for (u64 i = 0; i < thrdPrng.size(); i++)
            thrdPrng[i].SetSeed(mPrng.get<block>());

        auto RsSeed = mPrng.get<block>();

		std::vector<std::vector<u8>> sendBuff2(chls.size());

        auto routine = [&](u64 t)
        {
            u64 inputStartIdx = inputs.size() * t / chls.size();
            u64 inputEndIdx = inputs.size() * (t + 1) / chls.size();
            u64 subsetInputSize = inputEndIdx - inputStartIdx;


            auto& chl = chls[t];
            auto& prng = thrdPrng[t];

            using Curve = REllipticCurve;
            using Point = REccPoint;
            using Brick = REccPoint;
            using Number = REccNumber;
            Curve curve;


          
            RandomOracle inputHasher(sizeof(block));
			Number a(curve);
			Point xa(curve), point(curve), yb(curve), yba(curve);
            a.randomize(RsSeed);

			std::vector<u8> sendBuff(xa.sizeBytes() * subsetInputSize);
			auto sendIter = sendBuff.data();
			sendBuff2[t].resize(maskSizeByte * subsetInputSize);
			auto sendIter2 = sendBuff2[t].data();

			std::vector<u8> recvBuff(yb.sizeBytes() * subsetInputSize);
            std::vector<u8> temp(yba.sizeBytes());

			//send H(x)^a
            for (u64 i = inputStartIdx ; i < inputEndIdx; ++i)
            {
                block seed;
                inputHasher.Reset();
                inputHasher.Update(inputs[i]);
                inputHasher.Final(seed);

				point.randomize(seed);
                //std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

				xa = (point * a);
#ifdef PRINT
				if (i == 0)
					std::cout << "xa[" << i << "] " << xa << std::endl;
#endif	
				xa.toBytes(sendIter);
				sendIter += xa.sizeBytes();
            }
			chl.asyncSend(std::move(sendBuff));

    
			//recv H(y)^b
			chl.recv(recvBuff);
			if (recvBuff.size() != subsetInputSize * yb.sizeBytes())
			{
				std::cout << "error @ " << (LOCATION) << std::endl;
				throw std::runtime_error(LOCATION);
			}
			auto recvIter = recvBuff.data();

			//send H(y)^b^a
            for (u64 i = inputStartIdx; i < inputEndIdx;i++)
            {
				yb.fromBytes(recvIter); recvIter += yb.sizeBytes();
				yba = yb*a;

                
                yba.toBytes(temp.data());
                RandomOracle ro(sizeof(block));
                ro.Update(temp.data(), temp.size());
                block blk;
                ro.Final(blk);
                memcpy(sendIter2, &blk, maskSizeByte);
#ifdef PRINT
				if (i == 0)
				{
					std::cout << "yba[" << i << "] " << yba << std::endl;
					std::cout << "temp[" << i << "] " << toBlock(temp) << std::endl;
					std::cout << "sendIter2[" << i << "] " << toBlock(sendIter2) << std::endl;
				}
#endif
				sendIter2 += maskSizeByte;
            }
			//std::cout << "dones send H(y)^b^a" << std::endl;
	
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

		for (u64 i = 0; i < u64(chls.size()); ++i)
		{
			thrds[i] = std::thread([=] {
				auto& chl = chls[i];
				chl.asyncSend(std::move(sendBuff2[i]));
			});
		}


		for (auto& thrd : thrds)
			thrd.join();

		//std::cout << "S done" << std::endl;

    }
}

#endif