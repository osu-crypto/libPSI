#include "libPSI/config.h"
#ifdef ENABLE_DKT_PSI
#ifndef ENABLE_RELIC
#pragma error("ENABLE_RELIC must be defined in libOTe")
#endif

#include "DktMPsiReceiver.h"
#include "cryptoTools/Crypto/RCurve.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Common/Log.h"

#include <unordered_map>

namespace osuCrypto
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
        span<block> inputs,
        span<Channel> chls)
    {
        std::vector<PRNG> thrdPrng(chls.size());
        for (u64 i = 0; i < thrdPrng.size(); i++)
            thrdPrng[i].SetSeed(mPrng.get<block>());


        u64 theirInputSize = inputs.size();


        auto RcSeed = mPrng.get<block>();


        std::vector<std::future<block>> 
            sigmaHashsFutures(chls.size() - 1),
            sigma2HashsFutures(chls.size() - 1);
        std::vector<std::promise<block>>
            sigmaHashsProms(chls.size() - 1),
            sigma2HashsProms(chls.size() - 1);


        struct InputHash
        {
            InputHash() {}
            InputHash(block m, u64 i) : mHash(m), mInputIdx(i) {}
            block mHash;
            u64 mInputIdx;
        };
        std::vector<std::promise<std::vector<InputHash>*>> inputHashProms(chls.size() - 1);
        std::vector<std::future<std::vector<InputHash>*>> inputHashFutrs(chls.size() - 1);

        std::promise<void> mergedHashTableProm;
        std::shared_future<void> mergedHashTableFutr = mergedHashTableProm.get_future().share();

        std::promise<std::array<REccNumber*, 2>> sigmaValsProm;
        std::shared_future<std::array<REccNumber*, 2>> sigmaValsFutr(sigmaValsProm.get_future().share());
        std::promise<std::tuple<REccNumber*, REccNumber*, REccPoint*>> sigma2ValsProm;
        std::shared_future<std::tuple<REccNumber*, REccNumber*, REccPoint*>> sigma2ValsFutr(sigma2ValsProm.get_future().share());
        std::vector<std::vector<u64>> localIntersections(chls.size()-1);
        std::unordered_map<u64, InputHash> hashs;


        for (u64 i = 0; i < sigmaHashsFutures.size(); i++)
        {
            sigmaHashsFutures[i] = sigmaHashsProms[i].get_future();
            sigma2HashsFutures[i] = sigma2HashsProms[i].get_future();
            inputHashFutrs[i] = inputHashProms[i].get_future();
        }


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

            // curve must be prime order...
            REllipticCurve curve;
            
            if (curve.getOrder().isPrime() == false)
                throw std::runtime_error("must be prime");

            //if (curve.getGenerators().size() < 3)
            //{
            //    std::cout << ("DktMPsi require at least 3 generators") << std::endl;
            //    throw std::runtime_error("DktMPsi require at least 3 generators");
            //}

            const auto g = curve.getGenerator();
            REccPoint gg; gg.randomize(ZeroBlock);
            REccPoint ggg; gg.randomize(OneBlock);
            auto g2 = gg + ggg;

            typedef REccPoint BRICK;

            BRICK gBrick(g);
            BRICK ggBrick(gg);
            BRICK gggBrick(ggg);


            std::vector<REccPoint> inputPoints;
            inputPoints.reserve(inputs.size());

            REccPoint pch(curve);


            for (u64 i = myInputStartIdx; i < myInputEndIdx; ++i)
            {

                RandomOracle inputHasher;
                inputHasher.Update(inputs[i]);
                inputHasher.Final(hashOut);

                inputPoints.emplace_back(curve);
                auto& point = inputPoints.back();

                point.randomize(toBlock(hashOut));

                if (i == myInputStartIdx)
                    pch = point;
                else
                    pch = pch + point;
            }

            REccNumber Rc(curve);
            REccNumber sigmaD(curve);
            Rc.randomize(RcSeed);
            sigmaD.randomize(prng);


            REccPoint X(curve), sigmaA(curve);
            auto gRc = gBrick * Rc;
            X = pch + gRc;


            sigmaA = gBrick * sigmaD;
            RandomOracle sigmaHasher;

            if (t == 0)
            {
                std::vector<u8> sendBuff(X.sizeBytes() * 2);
                auto iter = sendBuff.data();
                X.toBytes(iter); iter += X.sizeBytes();
                sigmaA.toBytes(iter);
                sigmaHasher.Update(iter, sigmaA.sizeBytes());

                chl.asyncSend(std::move(sendBuff));
            }


            std::vector<REccPoint> pchs, Ms, Ns, sigmaBs, sigma2As;
            pchs.reserve(subsetInputSize);
            Ms.reserve(subsetInputSize);
            Ns.reserve(subsetInputSize);
            sigmaBs.reserve(subsetInputSize);
            sigma2As.reserve(subsetInputSize);

            std::vector<REccNumber> Rcs, sigmaDs, sigmaPhis;
            Rcs.reserve(subsetInputSize);
            sigmaDs.reserve(subsetInputSize);
            sigmaPhis.reserve(subsetInputSize);


            const u64 stepSize = 64;


            for (u64 i = myInputStartIdx; i < myInputEndIdx;)
            {
                auto curStepSize = std::min(stepSize, myInputEndIdx - i);


				std::vector<u8> sendBuff(g.sizeBytes() * 3 * curStepSize);
                auto iter = sendBuff.data();

                for (u64 j = 0; j < curStepSize; ++j, ++i)
                {
                    sigmaDs.emplace_back(curve);
                    sigmaBs.emplace_back(curve);
                    pchs.emplace_back(curve);
                    Rcs.emplace_back(curve);
                    Ms.emplace_back(curve);
                    Ns.emplace_back(curve);


                    sigmaDs.back().randomize(prng);
                    sigmaBs.back() = g2 * sigmaDs.back();

                    pchs.back() = pch - inputPoints.back();

                    Rcs.back().randomize(prng);
                    auto grc = ggBrick * Rcs.back();
                    Ms.back() = inputPoints.back() + grc;

                    Ns.back() = pchs.back() + gggBrick  * Rcs.back();


                    Ms.back().toBytes(iter); iter += Ms.back().sizeBytes();
                    Ns.back().toBytes(iter); iter += Ns.back().sizeBytes();


                    sigmaBs.back().toBytes(iter);
                    sigmaHasher.Update(iter, sigmaBs.back().sizeBytes());
                    iter += Ns.back().sizeBytes();


                }
                chl.asyncSend(std::move(sendBuff));
            }



            REccNumber sigmaE(curve), sigmaPhi(curve);
            if (t == 0)
            {
                for (auto& fut : sigmaHashsFutures)
                {
                    sigmaHasher.Update(fut.get());
                }

                sigmaHasher.Final(hashOut);
                sigmaE.randomize(toBlock(hashOut));
                sigmaPhi = sigmaD + Rc * sigmaE;

                sigmaValsProm.set_value({ &sigmaE, &sigmaPhi });


                std::vector<u8> sendBuff(sigmaPhi.sizeBytes());
                sigmaPhi.toBytes(sendBuff.data());
                chl.asyncSend(std::move(sendBuff));
            }
            else
            {
                sigmaHasher.Final(hashOut);

                sigmaHashsProms[t - 1].set_value(toBlock(hashOut));

                auto rr = sigmaValsFutr.get();
                sigmaE = *rr[0];
                sigmaPhi = *rr[1];
            }

            //std::cout << IoStream::lock << "r e        " << sigmaE << std::endl << IoStream::unlock;





            REccNumber one(curve, 1);
            REccNumber zero(curve, 0);

            //std::cout << "r g^z      " << sigmaGZ << std::endl;

            for (u64 i = myInputStartIdx, ii = 0; i < myInputEndIdx;)
            {
                auto curStepSize = std::min(stepSize, myInputEndIdx - i);


                std::vector<u8> sendBuff(sigmaPhi.sizeBytes() * curStepSize);
                auto iter = sendBuff.data();

                for (u64 j = 0; j < curStepSize; ++j, ++i, ++ii)
                {
                    sigmaPhis.emplace_back(curve);
                    sigmaPhis[ii] = sigmaDs[ii] + Rcs[ii] * sigmaE;

                    if (sigmaPhis[ii].iszero())
                    {
                        std::cout << "zero " << ii << "  " << t << std::endl;
                    }

                    sigmaPhis[ii].toBytes(iter); iter += sigmaPhis[ii].sizeBytes();

                    auto XMN = (X - (Ms[ii] + Ns[ii]));


                    //std::cout << "XMN    " << XMN << std::endl;
                    //std::cout << "sigmaE " << sigmaE << std::endl;
                    //auto t = XMN * sigmaE;

                    //auto proof = (sigmaA - sigmaBs[ii]) + t;
                    //auto checkVal = (g * sigmaPhi) - ((gg + ggg) * sigmaPhis[ii]);

                    //if (checkVal != proof)
                    //{
                    //    std::cout <<IoStream::lock << "r expected " << checkVal << std::endl;
                    //    std::cout << "r actual   " << proof << std::endl << std::endl << IoStream::unlock;
                    //    // bad sigma proof
                    //    //throw std::runtime_error(LOCATION);
                    //}
                    //else
                    //{

                    //    std::cout << IoStream::lock << "* expected " << checkVal << std::endl << IoStream::unlock;
                    //}
                }

                chl.asyncSend(std::move(sendBuff));
            }

            REccPoint Z(curve), Mpi(curve), Kci(curve), sigma2A(curve);
            REccNumber sigma2Phi(curve), sigma2C(curve);


            RandomOracle sigma2Hasher;
            if (t == 0)
            {

                std::vector<u8> buff;
                chl.recv(buff);
                if (buff.size() != sigma2A.sizeBytes()) throw std::runtime_error("");
                sigma2A.fromBytes(buff.data());
                sigma2Hasher.Update(buff.data(), buff.size());
            }

            for (u64 i = myInputStartIdx; i < myInputEndIdx;)
            {
                auto curStepSize = std::min(stepSize, myInputEndIdx - i);

				std::vector<u8> buff;
                chl.recv(buff);
                sigma2Hasher.Update(buff.data(), buff.size());

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

            if (t == 0)
            {
                for (auto& fut : sigma2HashsFutures)
                {
                    sigma2Hasher.Update(fut.get());
                }

                sigma2Hasher.Final(hashOut);
                sigma2C.randomize(toBlock(hashOut));

				std::vector<u8> buff(Z.sizeBytes() + sigma2Phi.sizeBytes());
                chl.recv(buff.data(), buff.size());
                Z.fromBytes(buff.data());
                sigma2Phi.fromBytes(buff.data() + Z.sizeBytes());
                //EccBrick ZBrick(Z);

                sigma2ValsProm.set_value(std::tuple<REccNumber*, REccNumber*, REccPoint*>{&sigma2C, &sigma2Phi, &Z });

                auto sigma2ggPhiExpected = sigma2A + Z * sigma2C;
                auto sigma2ggPhi = gg * sigma2Phi;

                if (sigma2ggPhiExpected != sigma2ggPhi)
                {
                    std::cout << "sender's sigma proof failed." << std::endl;
                    throw std::runtime_error("sender's sigma proof failed.");
                }



            }
            else
            {
                sigma2Hasher.Final(hashOut);

                sigma2HashsProms[t - 1].set_value(toBlock(hashOut));

                auto rr = sigma2ValsFutr.get();
                sigma2C = *std::get<0>(rr);// .first;
                sigma2Phi = *std::get<1>(rr);// .second;
                Z = *std::get<2>(rr);// .third;
            }

			std::vector<u8> buff2(Z.sizeBytes());

            std::vector<InputHash> hashVec;
            if (t == 0) hashs.reserve(inputs.size());
            else hashVec.resize(subsetInputSize);
            auto hashVecIter = hashVec.begin();


			std::vector<u8> buff;
            for (u64 i = myInputStartIdx, ii = 0; i < myInputEndIdx;)
            {
                auto curStepSize = std::min(stepSize, myInputEndIdx - i);

                chl.recv(buff);

                auto expected = curStepSize * Z.sizeBytes();
                if (buff.size() != expected)
                    throw std::runtime_error(LOCATION);

                auto iter = buff.data();
                for (u64 j = 0; j < curStepSize; ++j, ++i, ++ii)
                {

                    Mpi.fromBytes(iter); iter += Mpi.sizeBytes();

                    //REccPoint expectedMpi(curve);

                    //expectedMpi = Ms[i] * Rs;

                    auto negRcs = (zero - Rcs[ii]);
                    auto ZRcsi = Z * negRcs;
                    Kci = ZRcsi + Mpi;
                    //std::cout << "Kc[" << i << "] " << Kci << std::endl;

                    RandomOracle sha;
                    Kci.toBytes(buff2.data());
                    //std::cout << "buff " << buff << std::endl;

                    sha.Update(buff2.data(), Kci.sizeBytes());

                    inputPoints[ii].toBytes(buff2.data());
                    sha.Update(buff2.data(), inputPoints[ii].sizeBytes());

                    sha.Update(inputs[i]);


                    sha.Final(hashOut);

                    auto blk = toBlock(hashOut);
                    auto idx = *(u64*)&blk;
                    //std::cout << "r " << blk << "  " << idx << std::endl;
                    
                    if (t == 0)
                    {
                        hashs.insert({ idx , InputHash(blk, i) });
                    }
                    else
                    {
                        *hashVecIter++ = InputHash(blk, i);
                    }


                    auto sigma2MsiPhiExpected = sigma2As[ii] + Mpi * sigma2C;
                    auto sigma2MsiPhi = Ms[ii] * sigma2Phi;

                    if (sigma2MsiPhiExpected != sigma2MsiPhi)
                    {
                        std::cout << "sender's sigma proof failed (msi)." << std::endl;
                        throw std::runtime_error("sender's sigma proof failed (msi).");
                    }
                }
            }

            if (t == 0)
            {
                for (auto& fut : inputHashFutrs)
                {
                    auto* inputHashs = fut.get();
                    for (auto& inputHash : *inputHashs)
                    {
                        auto idx = *(u64*)&inputHash.mHash;
                        hashs.insert({ idx , inputHash });
                    }
                }


                mergedHashTableProm.set_value();
            }
            else
            {
                inputHashProms[t - 1].set_value(&hashVec);
                mergedHashTableFutr.get();
            }

			std::vector<block> view;
            for (u64 i = theirInputStartIdx; i < theirInputEndIdx; )
            {
                chl.recv(view);
                i += view.size();

                for (auto& Tsj : view)
                {
                    auto idx = *(u64*)&Tsj;
                    //std::cout << "recv " << Tsj << std::endl;
                    //std::cout << "idx " << idx << std::endl;
                    auto iter = hashs.find(idx);


                    if (iter != hashs.end())
                    {
                        //std::cout << "pm " << iter->second.mHash << "  " << iter->second.mInputIdx << std::endl;

                        if (eq(iter->second.mHash, Tsj))
                        {
                            if (t == 0)
                            {
                                mIntersection.emplace_back(iter->second.mInputIdx);
                            }
                            else
                            {
                                localIntersections[t-1].emplace_back(iter->second.mInputIdx);
                            }
                        }
                    }

                }

                // termination condition is sending one extra byte
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

        u64 extraSize = 0;
        for (u64 i = 0; i < thrds.size(); ++i)
        {
            thrds[i].join();
            extraSize = localIntersections[i].size();
        }

        mIntersection.reserve(mIntersection.size() + extraSize);
        for (u64 i = 0; i < thrds.size(); ++i)
        {
            mIntersection.insert(mIntersection.end(), localIntersections[i].begin(), localIntersections[i].end());
        }


    }
}
#endif
