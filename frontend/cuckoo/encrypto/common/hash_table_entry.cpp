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

#include "hash_table_entry.h"

namespace ENCRYPTO {
HashTableEntry::HashTableEntry(std::uint64_t value, std::size_t global_id,
                               std::size_t num_of_functions, std::size_t num_of_bins) {
  value_ = value;
  global_id_ = global_id;
  num_of_hash_functions_ = num_of_functions;
  num_of_bins_ = num_of_bins;
}

HashTableEntry::HashTableEntry(const HashTableEntry& other) {
  num_of_hash_functions_ = other.num_of_hash_functions_;
  num_of_bins_ = other.num_of_bins_;
  global_id_ = other.global_id_;

  value_ = other.value_;
  current_function_id_ = other.current_function_id_;
  possible_addresses_ = other.possible_addresses_;
}
}