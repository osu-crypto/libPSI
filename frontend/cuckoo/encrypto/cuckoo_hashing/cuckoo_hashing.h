#pragma once

//
// \file cuckoo_hashing.h
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

#include "../common/hash_table_entry.h"
#include "../common/hashing.h"

namespace ENCRYPTO {


class CuckooTable : public HashingTable {
 public:
  CuckooTable() = delete;

  CuckooTable(double epsilon) : CuckooTable(epsilon, 0, 0){};

  CuckooTable(double epsilon, std::size_t seed) : CuckooTable(epsilon, 0, seed){};

  CuckooTable(std::size_t num_of_bins) : CuckooTable(0.0f, num_of_bins, 0){};

  CuckooTable(std::size_t num_of_bins, std::size_t seed) : CuckooTable(0.0f, num_of_bins, seed){};

  ~CuckooTable() final{};

  bool Insert(std::uint64_t element) final;

  bool Insert(const std::vector<std::uint64_t>& elements) final;

  void SetRecursiveInsertionLimiter(std::size_t limiter);

  bool Print() const final;

  auto GetStatistics() const { return statistics_; }

  auto GetStashSize() const { return stash_.size(); }

  std::vector<uint64_t> AsRawVector() const final;

  std::vector<std::size_t> GetNumOfElementsInBins() const final;

 private:
  std::vector<HashTableEntry> hash_table_, stash_;
  std::size_t recursion_limiter_ = 200;

  struct Statistics {
    std::size_t recursive_remappings_counter_ = 0;
  } statistics_;

  CuckooTable(double epsilon, std::size_t num_of_bins, std::size_t seed);

  bool AllocateTable() final;

  bool MapElementsToTable() final;
};
}