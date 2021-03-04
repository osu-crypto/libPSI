#pragma once

//
// \file hashing.h
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

#include <cassert>
#include <iostream>
#include <random>
#include <vector>

namespace ENCRYPTO {

class HashingTable {
 public:
  HashingTable(double epsilon) { epsilon_ = epsilon; };
  virtual ~HashingTable() = default;

  virtual bool Insert(std::uint64_t element) = 0;
  virtual bool Insert(const std::vector<std::uint64_t>& elements) = 0;

  virtual bool Print() const = 0;

  virtual std::vector<uint64_t> AsRawVector() const = 0;

  virtual std::vector<std::size_t> GetNumOfElementsInBins() const = 0;

  void SetNumOfHashFunctions(std::size_t n) { num_of_hash_functions_ = n; }

  bool MapElements();

  static std::uint64_t ElementToHash(std::uint64_t element);

 protected:
  HashingTable() = default;

  std::vector<std::uint64_t> elements_;

  // binning
  double epsilon_ = 1.2f;
  std::size_t num_bins_ = 0;

  std::size_t elem_byte_length_ = 8;
  std::size_t num_of_hash_functions_ = 3;

  // randomness
  std::size_t seed_ = 0;
  std::mt19937_64 generator_;

  // LUTs
  std::size_t num_of_luts_ = 5;
  std::size_t num_of_tables_in_lut_ = 32;
  std::vector<std::vector<std::vector<std::uint64_t>>> luts_;

  bool mapped_ = false;

  virtual bool AllocateTable() = 0;
  virtual bool MapElementsToTable() = 0;

  bool AllocateLUTs();

  bool GenerateLUTs();

  std::vector<std::uint64_t> HashToPosition(uint64_t element) const;
};

}