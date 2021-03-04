#pragma once

//
// \file hash_table_entry.h
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

#include <iostream>
#include <vector>

namespace ENCRYPTO {
constexpr auto DUMMY_ELEMENT = std::numeric_limits<std::size_t>::max();

class HashTableEntry {
 public:
  HashTableEntry() { global_id_ = value_ = DUMMY_ELEMENT; }

  HashTableEntry(std::uint64_t value, std::size_t global_id, std::size_t num_of_functions,
                 std::size_t num_of_bins);
  HashTableEntry(const HashTableEntry& other);

  void SetCurrentAddress(std::size_t function_id) { current_function_id_ = function_id; }

  void SetPossibleAddresses(std::vector<std::size_t>&& addresses) {
    possible_addresses_ = std::move(addresses);
  }

  std::size_t GetAddressAt(std::size_t function_id) const {
    return possible_addresses_.at(function_id) % num_of_bins_;
  }

  std::size_t GetCurrentFunctinId() const { return current_function_id_; }

  std::size_t GetCurrentAddress() const {
    return possible_addresses_.at(current_function_id_) % num_of_bins_;
  }

  const std::vector<std::size_t> GetPossibleAddresses() const { return possible_addresses_; };

  bool IsEmpty() const { return value_ == DUMMY_ELEMENT; }

  std::size_t GetGlobalID() const { return global_id_; }

  std::uint64_t GetElement() const { return value_; }

  void IterateFunctionNumber() {
    current_function_id_ = (current_function_id_ + 1) % num_of_hash_functions_;
  }

  friend void swap(HashTableEntry& a, HashTableEntry& b) noexcept;

 private:
  std::size_t num_of_hash_functions_;
  std::size_t num_of_bins_;
  std::size_t global_id_;

  uint64_t value_;
  std::size_t current_function_id_;
  std::vector<std::size_t> possible_addresses_;
};
}