#pragma once
#include "Common/Defines.h"
#define AES_DECRYPTION
#include <wmmintrin.h>

namespace osuCrypto {

#define AES_BLK_SIZE 16



    class AES
    {
    public:

        AES();
        AES(const block& userKey);


        void setKey(const block& userKey);


        void ecbEncBlock(const block& plaintext, block& cyphertext) const;
        block ecbEncBlock(const block& plaintext) const;

        void ecbEncBlocks(const block* plaintexts, u64 blockLength, block* cyphertext) const;

        void ecbEncTwoBlocks(const block* plaintexts, block* cyphertext) const;
        void ecbEncFourBlocks(const block* plaintexts, block* cyphertext) const;

        block mRoundKey[11];
    };


    extern     const AES mAesFixedKey;

    class AESDec
    {
    public:

        AESDec();
        AESDec(const block& userKey);

        void setKey(const block& userKey);

        void ecbDecBlock(const block& cyphertext, block& plaintext);
        block ecbDecBlock(const block& cyphertext);
        block mRoundKey[11];
    };

}
