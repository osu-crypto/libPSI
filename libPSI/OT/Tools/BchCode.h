#pragma once
#include "Common/Defines.h"
#include "Common/ArrayView.h"
#include <string>
//#include "NTL/matrix.h"
//#include "NTL/matrix.h"
namespace osuCrypto
{

    class BchCode
    {
    public:
        BchCode();
        ~BchCode();


        void loadTxtFile(const std::string& fileName);
        void loadTxtFile(std::istream& in);



        void loadBinFile(const std::string& fileName);
        void loadBinFile(std::istream& in);

        void writeBinFile(const std::string& fileName);
        void writeBinFile(std::ostream& out);

        u64 mCodewordBitSize;
        std::vector<block> mG;

        u64 plaintextBlkSize()const;
        u64 codewordBlkSize()const;

        u64 plaintextBitSize()const;
        u64 codewordBitSize()const;


        void encode(ArrayView<block> plaintext, ArrayView<block> codeword);

    };

}
