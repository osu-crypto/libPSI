
#include "libPSI/config.h"
#ifdef ENABLE_DKT_PSI
#ifndef ENABLE_RELIC
#pragma error("ENABLE_RELIC must be defined in libOTe")
#endif
#include "DktMPsiSender.h"
#include "cryptoTools/Crypto/RCurve.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Network/Channel.h"

namespace osuCrypto
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


    void DktMPsiSender::sendInput(std::vector<block>& inputs, span<Channel> chls)
    {


        u64 theirInputSize = inputs.size();

        std::vector<std::future<std::array<block,2>>> sigmaHashsFutures(chls.size() - 1);
        std::vector<std::promise<std::array<block, 2>>> sigmaHashsProms(chls.size() - 1);
        std::vector<std::future<REccPoint*>> mPchsFutures(chls.size() - 1);
        std::vector<std::promise<REccPoint*>> mPchsProms(chls.size() - 1);

        for (u64 i = 0; i < mPchsFutures.size(); i++)
        {
            mPchsFutures[i] = mPchsProms[i].get_future();
            sigmaHashsFutures[i] = sigmaHashsProms[i].get_future();
        }

        std::vector<PRNG> thrdPrng(chls.size());
        for (u64 i = 0; i < thrdPrng.size(); i++)
            thrdPrng[i].SetSeed(mPrng.get<block>());

        std::promise<std::array<REccPoint*,3>> pchProm;
        std::shared_future<std::array<REccPoint*,3>> pchFuture(pchProm.get_future().share());

        std::promise<std::tuple<REccNumber*, REccNumber*, REccPoint*>> sigma2PhiProm;
        std::shared_future<std::tuple<REccNumber*, REccNumber*, REccPoint*>> sigma2PhiFuture = sigma2PhiProm.get_future();


        //EccNumber Rs(curve);
        //Rs.randomize(mPrng);

        auto RsSeed = mPrng.get<block>();
        auto sigma2RSeed = mPrng.get<block>();

        auto routine = [&](u64 t)
        {
            u64 myInputStartIdx = inputs.size() * t / chls.size();
            u64 myInputEndIdx = inputs.size() * (t + 1) / chls.size();
            u64 subsetInputSize = myInputEndIdx - myInputStartIdx;

            u64 theirInputStartIdx = theirInputSize * t / chls.size();
            u64 theirInputEndIdx = theirInputSize * (t + 1) / chls.size();

            auto& chl = chls[t];
            auto& prng = thrdPrng[t];
            u8 hashOut[RandomOracle::HashSize];

            REllipticCurve curve;
            const auto g = curve.getGenerator();
            REccPoint gg; gg.randomize(ZeroBlock);
            REccPoint ggg; gg.randomize(OneBlock);
            auto g2 = gg + ggg;

            typedef REccPoint BRICK;
            BRICK gBrick(g);

            REccPoint pch(curve);
            RandomOracle inputHasher,sigmaHasher, sigma2Hasher;
            std::vector<REccPoint> inputPoints;
            inputPoints.reserve(myInputEndIdx - myInputStartIdx);

            REccNumber Rs(curve);
            Rs.randomize(RsSeed);

            REccPoint Z(curve), X(curve), sigmaA(curve);
            Z = gg * Rs;


            for (u64 i = myInputStartIdx; i < myInputEndIdx; ++i)
            {

                inputHasher.Reset();
                inputHasher.Update(inputs[i]);
                inputHasher.Final(hashOut);

                inputPoints.emplace_back(curve);

                auto& point = inputPoints.back();

                PRNG inputPrng(toBlock(hashOut));
                point.randomize(inputPrng);
                //std::cout << "sp  " << point << "  " << toBlock(hashOut) << std::endl;

                if (i == myInputStartIdx)
                    pch = point;
                else
                    pch = pch + point;
            }


            if (t == 0)
            {
                for (u64 i = 0; i < mPchsFutures.size(); ++i)
                {
                    auto otherPch = *mPchsFutures[i].get();
                    //otherPch.setCurve(curve);

                    pch += otherPch;
                }

                std::vector<u8> buff(X.sizeBytes() * 2);
                chl.recv(buff.data(), buff.size());
                X.fromBytes(buff.data());
                sigmaA.fromBytes(buff.data() + X.sizeBytes());

                sigmaHasher.Update(buff.data() + X.sizeBytes(), sigmaA.sizeBytes());


                pchProm.set_value({ &pch, &X, &sigmaA });
            }
            else
            {
                mPchsProms[t - 1].set_value(&pch);

                auto  rr = pchFuture.get();
                pch = *rr[0];
                X = *rr[1];
                sigmaA = *rr[2];
            }

            //pchSemaphore.decrementWait();



            //std::cout << "sZ  " << Z << std::endl;

            std::vector<REccNumber> sigmaPhis;
            std::vector<REccPoint> Ms, Ns, Mps, sigmaBs, sigma2As;
            Ms.reserve(subsetInputSize);
            Ns.reserve(subsetInputSize);
            Mps.reserve(subsetInputSize);
            sigmaBs.reserve(subsetInputSize);
            sigmaPhis.reserve(subsetInputSize);
            sigma2As.reserve(subsetInputSize);

			std::vector<u8> buff;
            buff.resize(X.sizeBytes() * 2);
            const u64 stepSize = 64;


            REccNumber sigma2R(curve);
            sigma2R.randomize(sigma2RSeed);

            if (t == 0)
            {

                REccPoint sigma2A = gg * sigma2R;
				std::vector<u8> sendBuff(sigma2A.sizeBytes());
                sigma2A.toBytes(sendBuff.data());

                sigma2Hasher.Reset();
                sigma2Hasher.Update(sendBuff.data(), sendBuff.size());

                chl.asyncSend(std::move(sendBuff));
            }


            //EccPoint sigma2Ai(curve);
            for (u64 i = theirInputStartIdx; i < theirInputEndIdx;)
            {
                auto curStepSize = std::min(stepSize, theirInputEndIdx - i);

				std::vector<u8> sendBuff(Z.sizeBytes() * curStepSize);

                chl.recv(buff);

                if (buff.size() != curStepSize * Z.sizeBytes() * 3)
                {

                    std::cout << "error @ " <<(LOCATION) << std::endl;
                    throw std::runtime_error(LOCATION);
                }
                auto iter = buff.data();
                auto sendIter = sendBuff.data();

                for (u64 j = 0; j < curStepSize; ++j, ++i)
                {
                    Ms.emplace_back(curve);
                    Ns.emplace_back(curve);
                    Mps.emplace_back(curve);
                    sigmaBs.emplace_back(curve);

                    Ms.back().fromBytes(iter); iter += Ms.back().sizeBytes();
                    Ns.back().fromBytes(iter); iter += Ns.back().sizeBytes();
                    sigmaBs.back().fromBytes(iter);

                    sigmaHasher.Update(iter, sigmaBs.back().sizeBytes());
                    iter += sigmaBs.back().sizeBytes();


                    Mps.back() = Ms.back() * Rs;

                    sigma2As.emplace_back(curve);
                    auto& sigma2Ai = sigma2As.back();
                    sigma2Ai = Ms.back() * sigma2R;
                    sigma2Ai.toBytes(sendIter); sendIter += sigma2Ai.sizeBytes();

                }

                sigma2Hasher.Update(sendBuff.data(), sendBuff.size());
                chl.asyncSend(std::move(sendBuff));
                //std::cout << " buff  " << (u32)buff.data()[10] << std::endl;
                //std::cout << " M.back()  " << Ms.back() << std::endl;
                //std::cout << " Mp.back() " << Mps.back() << std::endl;
                //std::cout << " Rs " << Rs << std::endl;

                //std::cout << "mps"
            }


            REccNumber sigmaE(curve), sigmaPhi(curve), sigma2Phi(curve);
            REccPoint sigmaGZ(curve);

            if (t == 0)
            {

                for (u64 i = 0; i < sigmaHashsFutures.size(); ++i)
                {
                    auto partialHashs = sigmaHashsFutures[i].get();
                    sigmaHasher.Update(partialHashs[0]);
                    sigma2Hasher.Update(partialHashs[1]);
                }


                sigma2Hasher.Final(hashOut);
                auto sigma2Seed = toBlock(hashOut);

                REccNumber sigma2C(curve);
                sigma2C.randomize(sigma2Seed);

                sigma2Phi = sigma2R + sigma2C * Rs;



				std::vector<u8> sendBuff(Z.sizeBytes() + sigma2Phi.sizeBytes());
                Z.toBytes(sendBuff.data());
                sigma2Phi.toBytes(sendBuff.data() + Z.sizeBytes());
                chl.asyncSend(std::move(sendBuff));



                sigmaHasher.Final(hashOut);
                sigmaE.randomize(toBlock(hashOut));
                //std::cout << IoStream::lock << "s e        " << sigmaE << std::endl << IoStream::unlock;


                chl.recv(buff);
                sigmaPhi.fromBytes(buff.data());

                sigmaGZ = gBrick * sigmaPhi;


                sigma2PhiProm.set_value(std::tuple<REccNumber*, REccNumber*, REccPoint*>{ &sigmaE,&sigma2Phi, &sigmaGZ });

            }
            else
            {
                std::array<block, 2> hashes;

                sigmaHasher.Final(hashOut);
                hashes[0] = toBlock(hashOut);
                sigma2Hasher.Final(hashOut);
                hashes[1] = toBlock(hashOut);

                sigmaHashsProms[t - 1].set_value(hashes);

                auto rr  = sigma2PhiFuture.get();
                sigmaE = *std::get<0>(rr);
                sigma2Phi = *std::get<1>(rr);
                sigmaGZ = *std::get<2>(rr);;
            }






            //std::cout << "s g^z      " << sigmaGZ << std::endl;
            //EccNumber zero(curve, 0);


            for (u64 i = theirInputStartIdx, ii = 0; i < theirInputEndIdx;)
            {
                auto curStepSize = std::min(stepSize, theirInputEndIdx - i);

                chl.recv(buff);

                if (buff.size() != curStepSize * sigmaPhi.sizeBytes())
                {
                    std::cout << "error @ " << (LOCATION) << std::endl;
                    throw std::runtime_error(LOCATION);
                }
                auto iter = buff.data();

                for (u64 j = 0; j < curStepSize; ++j, ++i, ++ii)
                {
                    sigmaPhis.emplace_back(curve);
                    sigmaPhis[ii].fromBytes(iter); iter += sigmaPhis[ii].sizeBytes();

                    //sigmaZs[ii] = zero - sigmaZs[ii];

                    auto checkVal = sigmaGZ - (g2 * sigmaPhis[ii]);
                    auto proof = sigmaA - sigmaBs[ii] + (X - (Ms[ii] + Ns[ii])) * sigmaE;


                    if (checkVal != proof)
                    {

                        std::cout << "Bad sigma Proof " << sigmaPhis[ii] << std::endl;
                        std::cout << "s sigmaPhis " << sigmaPhis[ii] << std::endl;
                        std::cout << "s expected  " << checkVal << std::endl;
                        std::cout << "s actual    " << proof << std::endl;
                        // bad sigma proof
                        //throw std::runtime_error(LOCATION);
                    }
                }
            }


            for (u64 i = 0; i < Mps.size();)
            {

                auto curStepSize = std::min(stepSize, Mps.size() - i);
				std::vector<u8> sendBuff(Z.sizeBytes() * curStepSize);
                auto iter = sendBuff.data();


                for (u64 j = 0; j < curStepSize; ++j, ++i)
                {
                    Mps[i].toBytes(iter); iter += Mps[i].sizeBytes();
                }

                chl.asyncSend(std::move(sendBuff));
            }


            RandomOracle outputHasher;
            REccPoint Ksj(curve);

            for (u64 i = myInputStartIdx, ii = 0; i < myInputEndIdx;)
            {

				std::vector<block> view(std::min(myInputEndIdx - i, u64(512)));

                for (u64 j = 0; j < u64(view.size()); ++i, ++j, ++ii)
                {

                    Ksj = inputPoints[ii] * Rs;
                    //std::cout << "Ks[" << i << "] " << Ksj << std::endl;

                    outputHasher.Reset();
                    Ksj.toBytes(buff.data());
                    outputHasher.Update(buff.data(), Ksj.sizeBytes());

                    inputPoints[ii].toBytes(buff.data());
                    outputHasher.Update(buff.data(), inputPoints[ii].sizeBytes());

                    outputHasher.Update(inputs[i]);

                    outputHasher.Final(hashOut);


                    //std::cout << "s " << toBlock(hashOut) << std::endl;

                    view[j] = toBlock(hashOut);
                }

                chl.asyncSend(std::move(view));
            }


        };


        std::vector<std::thread> thrds(chls.size()-1);
        for (u64 i = 1; i < u64(chls.size()); ++i)
        {
            thrds[i - 1] = std::thread([=] {
                routine(i);
            });
        }

        routine(0);

        for (auto& thrd : thrds)
            thrd.join();



    }
}
#endif