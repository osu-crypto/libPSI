//#include "stdafx.h"
#ifdef ENABLE_DCW_PSI
#include <thread>
#include <vector>
#include <memory>

#include "Common.h"
#include "cryptoTools/Common/Defines.h"
#include "libPSI/MPSI/Dcw/ShamirSSScheme.h" 
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Crypto/PRNG.h"
using namespace osuCrypto;

//namespace osuCrypto_tests
//{
void ShamirSSScheme_Test()
{
    u64 n = 100, k = 50;


    ShamirSSScheme ss;
    auto secret = ss.init(n, k);


    std::vector<block> shares(n);

    //if(ss.GetSecretParts()[0].size())

    ss.computeShares(shares);

    //for (u64 i = 0; i < n; ++i)
    //{
    //    NTL::BytesFromZZ((u8*)&shares[i], ss.GetSecretParts()[i], sizeof(block));
    //}


    std::vector<u32> idxs(k);
    std::vector<block> nums(k); 
    for (u64 i = 0; i < k; ++i)
    {
        idxs[i] = (u32)i;
        //NTL::ZZFromBytes(nums[i], (u8*)&shares[i], sizeof(block));
        nums[i] = shares[i];

        //std::cout << "shares[" << i << "] = " << shares[i] << std::endl;
    }

    //auto recovered = ss.getSecret(idxs, nums);
    auto recovered2 = ss.reconstruct(idxs, nums);




    //if( neq(secret, recovered))
    //    throw UnitTestFail();



    if (neq(secret, recovered2))
    {

        std::cout << secret << "  " << recovered2 << std::endl;
        throw UnitTestFail();

    }
}
#endif