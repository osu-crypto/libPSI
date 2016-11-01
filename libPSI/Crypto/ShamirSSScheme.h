#pragma once
//#include "NTL/ZZ_pEX.h"
#include <vector> 
#include "Common/Defines.h"
#include "Common/ArrayView.h"
#include "NTL/GF2EX.h"

namespace osuCrypto
{

    class ShamirSSScheme
    {


    public: 
        ShamirSSScheme();
        ~ShamirSSScheme(void);

        NTL::GF2X initGF2X(u64 n, u64 k);
        block init(u64 n, u64 k);

        void computeShares(ArrayView<block> shares, u64 theadCount = 0);
        void computeShares(ArrayView<NTL::GF2X> shares);


        block reconstruct(const std::vector<u32>& vPeople, const std::vector<block> &vPeopleSecrets);
        NTL::GF2X reconstruct(const std::vector<u32>& vPeople, const std::vector<NTL::GF2X> &vPeopleSecrets);

        NTL::GF2X mPrime; // the prime number for modulo opration 
    private:
        std::vector<NTL::GF2X> m_vPolynom; 
        // coef of base polynom[0] = the secret  

        //NTL::GF2X u32ToGf2X(u32);

        u64 m_nN; // total number of people which have a piece of secret 
        u64 m_nK; // nr of people need to discover the secret 

    };

}
