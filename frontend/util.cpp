#include "util.h"

using namespace osuCrypto;
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/ByteStream.h"
#define tryCount 2

void senderGetLatency(Channel& chl)
{

    u8 dummy[1];

    chl.asyncSend(dummy, 1);



    chl.recv(dummy, 1);
    chl.asyncSend(dummy, 1);


    Buff oneMbit((1 << 20) / 8);
    for (u64 i = 0; i < tryCount; ++i)
    {
        chl.recv(dummy, 1);

        for(u64 j =0; j < (1<<10); ++j)
            chl.asyncSend(oneMbit.data(), oneMbit.size());
    }
    chl.recv(dummy, 1);

}

void recverGetLatency(Channel& chl)
{

    u8 dummy[1];
    chl.recv(dummy, 1);
    Timer timer;
    auto start = timer.setTimePoint("");
    chl.asyncSend(dummy, 1);


    chl.recv(dummy, 1);

    auto mid = timer.setTimePoint("");
    auto recvStart = mid;
    auto recvEnd = mid;

    auto rrt = mid - start;
    std::cout << "latency:   " << std::chrono::duration_cast<std::chrono::milliseconds>(rrt).count() << " ms" << std::endl;
                 
    Buff oneMbit((1 << 20) / 8);
    for (u64 i = 0; i < tryCount; ++i)
    {
        recvStart = timer.setTimePoint("");
        chl.asyncSend(dummy, 1);

        for (u64 j = 0; j < (1 << 10); ++j)
            chl.recv(oneMbit);

        recvEnd = timer.setTimePoint("");

        // nanoseconds per GegaBit
        auto uspGb = std::chrono::duration_cast<std::chrono::nanoseconds>(recvEnd - recvStart - rrt / 2).count();

        // nanoseconds per second
        double usps = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::seconds(1)).count();

        // MegaBits per second
        auto Mbps = usps / uspGb *  (1 << 10);

        std::cout << "bandwidth: " << Mbps << " Mbps" << std::endl;
    }

    chl.asyncSend(dummy, 1);

}

void printTimings(
    std::string tag,
    std::vector<osuCrypto::Channel *> &chls,
    long long offlineTime, long long onlineTime,
    LaunchParams & params,
    const osuCrypto::u64 &setSize,
    const osuCrypto::u64 &numThreads)
{
    u64 dataSent = 0, dataRecv(0);
    for (u64 g = 0; g < chls.size(); ++g)
    {
        dataSent += chls[g]->getTotalDataSent();
        dataRecv += chls[g]->getTotalDataRecv();
        chls[g]->resetStats();
    }
    double time = offlineTime + onlineTime;
    time /= 1000;
    auto Mbps = dataSent * 8 / time / (1 << 20);
    auto MbpsRecv = dataRecv * 8 / time / (1 << 20);

    if (params.mVerbose)
    {
        std::cout << std::setw(6) << tag << " n = " << setSize << "  threads = " << numThreads << "\n"
            << "      Total Time = " << time << " ms\n"
            << "         Total = " << offlineTime << " ms\n"
            << "          Online = " << onlineTime << " ms\n"
            << "      Total Comm = " << string_format("%4.2f", dataSent / std::pow(2.0, 20)) << ", " << string_format("%4.2f", dataRecv / std::pow(2.0, 20)) << " MB\n"
            << "       Bandwidth = " << string_format("%4.2f", Mbps) << ", " << string_format("%4.2f", MbpsRecv) << " Mbps\n" << std::endl;


        if (params.mVerbose > 1)
            std::cout << gTimer << std::endl;
    }
    else
    {
        std::cout << std::setw(6) << tag
            << std::setw(8) << setSize
            << std::setw(10) << numThreads
            << std::setw(14) << (offlineTime + onlineTime)
            << std::setw(14) << onlineTime 
            << std::setw(18) << (string_format("%4.2f", dataSent / std::pow(2.0, 20)) + ", " + string_format("%4.2f", dataRecv / std::pow(2.0, 20))) 
            << std::setw(18) << (string_format("%4.2f", Mbps) + ", " + string_format("%4.2f", MbpsRecv)) << std::endl;
    }
}


void printHeader()
{
    std::cout 
        << "protocol     n      threads      total(ms)    online(ms)     comm (MB)        bandwidth (Mbps)\n"
        << "------------------------------------------------------------------------------------------------"<< std::endl;
}