#pragma once




void simpleTest(int argc, char** argv);

void sweepE(
    const osuCrypto::u64 &setSize,
    const osuCrypto::u64 &h,
    double &e,
    const osuCrypto::u64 &t,
    const osuCrypto::u64 &numThrds,
    bool varyCuckooSize,
    const osuCrypto::u64 &stashSize,
    std::fstream &out);
