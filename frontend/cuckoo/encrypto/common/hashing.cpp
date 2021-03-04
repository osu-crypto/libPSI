//
// \file hashing.cpp
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
// \copyright The MIT License. Copyright 2019
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
// A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#include "hashing.h"
#include "cryptoTools/Crypto/RandomOracle.h"
//#include <openssl/sha.h>
#include "cryptoTools/Crypto/AES.h"
namespace ENCRYPTO {

    bool HashingTable::MapElements() {
        AllocateTable();
        MapElementsToTable();
        mapped_ = true;
        return true;
    }

    bool HashingTable::AllocateLUTs() {
        luts_.resize(num_of_hash_functions_);
        for (auto& luts : luts_) {
            luts.resize(num_of_luts_);
            for (auto& entry : luts) {
                entry.resize(num_of_tables_in_lut_);
            }
        }
        return true;
    }

    bool HashingTable::GenerateLUTs() {
        for (auto i = 0ull; i < num_of_hash_functions_; ++i) {
            for (auto j = 0ull; j < num_of_luts_; ++j) {
                for (auto k = 0ull; k < num_of_tables_in_lut_; k++) {
                    luts_.at(i).at(j).at(k) = generator_();
                }
            }
        }

        return true;
    }

    std::vector<std::uint64_t> HashingTable::HashToPosition(uint64_t element) const {
        std::vector<std::uint64_t> addresses;
        if (0)
        {
            oc::AES aes(oc::block(0, seed_));
            for (auto func_i = 0ull; func_i < num_of_hash_functions_; ++func_i) {
                oc::block ee(func_i, element);
                addresses.push_back(aes.ecbEncBlock(ee).as<std::uint64_t>()[0]);
            }
        }
        else
        {

            for (auto func_i = 0ull; func_i < num_of_hash_functions_; ++func_i) {
                std::uint64_t address = element;
                for (auto lut_i = 0ull; lut_i < num_of_luts_; ++lut_i) {
                    std::size_t lut_id = ((address >> (lut_i * elem_byte_length_ / num_of_luts_)) & 0x000000FFu);
                    lut_id %= num_of_tables_in_lut_;
                    address ^= luts_.at(func_i).at(lut_i).at(lut_id);
                }
                addresses.push_back(address);
            }
        }
        return addresses;
    }

    std::uint64_t HashingTable::ElementToHash(std::uint64_t element) {
        oc::RandomOracle ro(sizeof(std::uint64_t));

        ro.Update(reinterpret_cast<unsigned char*>(&element), sizeof(element));

        uint64_t result = 0;
        ro.Final(result);

        return result;
    }
}