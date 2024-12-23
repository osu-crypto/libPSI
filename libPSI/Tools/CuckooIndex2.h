#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include <atomic>

namespace osuCrypto
{

    namespace old
    {

        // The parameters that define a cuckoo table.
        struct CuckooParam
        {
            u64 mStashSize;
            double mBinScaler;
            u64 mNumHashes, mN;

            u64 numBins() { return static_cast<u64>(mN * mBinScaler); }
            u64 binMask() { return (1ull << log2ceil(numBins())) - 1; }
        };

        extern CuckooParam k2n32s40CuckooParam;
        extern CuckooParam k2n30s40CuckooParam;
        extern CuckooParam k2n28s40CuckooParam;
        extern CuckooParam k2n24s40CuckooParam;
        extern CuckooParam k2n20s40CuckooParam;
        extern CuckooParam k2n16s40CuckooParam;
        extern CuckooParam k2n12s40CuckooParam;
        extern CuckooParam k2n08s40CuckooParam;
        extern CuckooParam k2n07s40CuckooParam;
        extern CuckooParam k2n06s40CuckooParam;
        extern CuckooParam k2n05s40CuckooParam;
        extern CuckooParam k2n04s40CuckooParam;
        extern CuckooParam k2n03s40CuckooParam;
        extern CuckooParam k2n02s40CuckooParam;
        extern CuckooParam k2n01s40CuckooParam;

        // Two variants of the Cuckoo implementation.
        enum CuckooTypes
        {
            ThreadSafe,
            NotThreadSafe
        };

        // Two variants of the Cuckoo values.
        template<CuckooTypes M> struct CuckooStorage;

        // Thread safe version requires atomic u64
        template<> struct CuckooStorage<ThreadSafe> { std::atomic<u64> mVal; };

        // Not Thread safe version only requires u64.
        template<> struct CuckooStorage<NotThreadSafe> { u64 mVal; };


        // A cuckoo hashing implementation. The cuckoo hash table takes {value, index}
        // pairs as input and stores the index. 
        template<CuckooTypes Mode = ThreadSafe>
        class CuckooIndex
        {

        public:
            CuckooIndex();
            ~CuckooIndex();

            // the maximum number of hash functions that are allowed.
#define CUCKOOINDEX_MAX_HASH_FUNCTION_COUNT 3

            u64 mReinsertLimit = 200;
            u64 mNumBins, mNumBinMask;
            //std::vector<u8> mRandHashIdx;
            //PRNG mPrng;

            struct Bin
            {
                CuckooStorage<Mode> mS;

                Bin() {
                    mS.mVal = (-1);
                }
                Bin(u64 idx, u64 hashIdx) { mS.mVal = (idx | (hashIdx << 56)); }
                Bin(const Bin& b) { mS.mVal = (b.load()); }

                bool isEmpty() const { return  load() == u64(-1); }
                u64 idx() const { return  load() & (u64(-1) >> 8); }
                u64 hashIdx() const { return  load() >> 56; }



                void swap(u64& idx, u64& hashIdx)
                {
                    u64 newVal = idx | (hashIdx << 56);
                    auto oldVal = exchange(newVal);
                    idx = oldVal & (u64(-1) >> 8);
                    hashIdx = (oldVal >> 56);
                }

                template<CuckooTypes M = Mode>
                typename std::enable_if< M == ThreadSafe, u64>::type exchange(u64 newVal) { return mS.mVal.exchange(newVal, std::memory_order_relaxed); }
                template<CuckooTypes M = Mode>
                typename std::enable_if< M == ThreadSafe, u64>::type load() const { return mS.mVal.load(std::memory_order_relaxed); }


                template<CuckooTypes M = Mode>
                typename std::enable_if< M == NotThreadSafe, u64>::type exchange(u64 newVal) { auto v = mS.mVal; mS.mVal = newVal;  return v; }
                template<CuckooTypes M = Mode>
                typename std::enable_if< M == NotThreadSafe, u64>::type load() const { return mS.mVal; }
            };


            void print() const;


            void init(const u64& n, const u64& statSecParam, u64 stashSize, u64 h);
            void init(const CuckooParam& params);

            static CuckooParam selectParams(const u64& n, const u64& statSecParam, const u64& stashSize, const u64& h);

            // insert unhashed items into the table using the provided hashing seed. 
            // set startIdx to be the first idx of the items being inserted. When 
            // find is called, it will return these indexes.
            void insert(span<block> items, block hashingSeed, u64 startIdx = 0);

            // insert pre hashed items into the table. 
            // set startIdx to be the first idx of the items being inserted. When 
            // find is called, it will return these indexes.
            void insert(span<block> items, u64 startIdx = 0);

            // insert single index with pre hashed values with error checking
            void insert(const u64& IdxItem, const block& hashes);

            // insert several items with pre-hashed values with error checking
            void insert(span<u64> itemIdxs, span<block> hashs);

            // insert several items with pre-hashed values
            void insert(const u64& numInserts, const u64* itemIdxs, const block* hashs);

            void insertOne(u64 itemIdx, u64 hashIdx, u64 tryIdx);

            struct FindResult
            {
                u64 mInputIdx;
                u64 mCuckooPositon;

                operator bool() const
                {
                    return mInputIdx != ~0ull;
                }
            };

            // find a single item with pre-hashed values and error checking.
            FindResult find(const block& hash);

            // find several items with pre hashed values, the indexes that are found are written to the idxs array.
            void find(span<block> hashes, span<u64> idxs);

            // find several items with pre hashed values, the indexes that are found are written to the idxs array.
            void find(const u64& numItems, const  block* hashes, const u64* idxs);

            // checks that the cuckoo index is correct
            void validate(span<block> inputs, block hashingSeed);

            // Return the number of items in the stash.
            u64 stashUtilization() const;

            std::vector<block> mHashes;

            std::vector<Bin> mBins;
            std::vector<Bin> mStash;

            // The total number of (re)inserts that were required,
            u64 mTotalTries;

            // Compare two Index.
            bool operator==(const CuckooIndex& cmp)const;
            bool operator!=(const CuckooIndex& cmp)const;

            CuckooParam mParams;

            u64 getHash(const u64& inputIdx, const u64& hashIdx);

            //template <typename T, unsigned int b>
            //inline static T
            //    rotl(T v)
            //{
            //    static_assert(std::is_integral<T>::value, "rotate of non-integral type");
            //    static_assert(!std::is_signed<T>::value, "rotate of signed type");
            //    constexpr unsigned int num_bits{ std::numeric_limits<T>::digits };
            //    static_assert(0 == (num_bits & (num_bits - 1)), "rotate value bit length not power of two");
            //    constexpr unsigned int count_mask{ num_bits - 1 };
            //    constexpr unsigned int mb{ b & count_mask };
            //    using promoted_type = typename std::common_type<int, T>::type;
            //    using unsigned_promoted_type = typename std::make_unsigned<promoted_type>::type;
            //    return ((unsigned_promoted_type{ v } << mb)
            //        | (unsigned_promoted_type{ v } >> (-mb & count_mask)));
            //}


            //inline static block expand(const block& hash, const u8& numHash, const u64& num_bins, const u64& binMask)
            //{

            //    static_assert(CUCKOOINDEX_MAX_HASH_FUNCTION_COUNT < 5,
            //        "here we assume that we dont overflow the 16 byte 'block hash'. "
            //        "To assume that we can have at most 4 has function, i.e. we need  2*hashIdx + sizeof(u64) < sizeof(block)");

            //    assert(numHash <= 3);
            //    //static const u64 mask = (1ull << 40) - 1;
            //    auto& bytes = hash.as<const u8>();
            //    u64 h0 = *(u64*)bytes.data();
            //    u64 h1 = *(u64*)(bytes.data() + 4);
            //    u64 h2 = *(u64*)(bytes.data() + 8);

            //    while ((binMask & h0) >= num_bins)
            //        h0 = rotl<u64, 7>(h0);
            //    while ((binMask & h1) >= num_bins)
            //        h1 = rotl<u64, 7>(h1);
            //    while ((binMask & h2) >= num_bins)
            //        h2 = rotl<u64, 7>(h2);

            //    h0 = (binMask & h0);
            //    h1 = (binMask & h1);
            //    h2 = (binMask & h2);

            //    //h0 = h0 % num_bins;
            //    //h1 = h1 % num_bins;
            //    //h2 = h2 % num_bins;

            //    if (h0 >= num_bins)
            //        throw RTE_LOC;
            //    if (h1 >= num_bins)
            //        throw RTE_LOC;
            //    if (h2 >= num_bins)
            //        throw RTE_LOC;

            //    block ret = ZeroBlock;
            //    std::memcpy(&ret.as<u8>()[0], &h0, 5);
            //    std::memcpy(&ret.as<u8>()[5], &h1, 5);
            //    std::memcpy(&ret.as<u8>()[10], &h2, 5);
            //    return ret;
            //}

            //inline static u64 getHash2(const block& hash, const u8& hashIdx, const u64& num_bins)
            //{

            //    static_assert(CUCKOOINDEX_MAX_HASH_FUNCTION_COUNT < 4,
            //        "here we assume that we dont overflow the 16 byte 'block hash'. "
            //        "To assume that we can have at most 4 has function, i.e. we need  2*hashIdx + sizeof(u64) < sizeof(block)");
            //    //AES aes(block(0, hashIdx));
            //    //auto h = aes.ecbEncBlock(hash);
            //    //return (*(u64*)&h) % num_bins;
            //    //auto rr = (*(u64*)&hash.as<u8>()[hashIdx * 5]) & 1099511627775ull;
            //    //if (rr >= num_bins)
            //    //    throw RTE_LOC;
            //    //return rr;
            //    return mod64(*(u64*)(((u8*)&hash) + (2 * hashIdx)), num_bins);
            //}

            inline static u64 getHash(const block& hash, const u8& hashIdx, const u64& num_bins)
            {
                u8* ptr = (u8*)&hash;
                ptr += 2 * hashIdx;
                //if (ptr > &hash.as<u8>()[8])
                //    throw RTE_LOC;
                static_assert(CUCKOOINDEX_MAX_HASH_FUNCTION_COUNT < 4,
                    "here we assume that we dont overflow the 16 byte 'block hash'. "
                    "To assume that we can have at most 4 has function, i.e. we need  2*hashIdx + sizeof(u64) < sizeof(block)");


                u64 h = *(u64*)ptr;
                return h % num_bins;

                //auto& bytes = hash.as<const u8>();
                //u64& h = *(u64*)(bytes.data() + 4 * hashIdx);

                //auto binMask = (1ull << log2ceil(num_bins)) - 1;
                //while ((binMask & h) >= num_bins)
                //    h = rotl<u64, 7>(h);

                //return getHash2(hash, hashIdx, num_bins);
            }


            static u8 minCollidingHashIdx(u64 target, block& hashes, u8 numHashFunctions, u64 numBins);
        };
    }
}