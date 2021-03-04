//
// \file cuckoo_hashing.cpp
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

#include "cuckoo_hashing.h"

//#include <fmt/format.h>
#include <string>

#include "../common/hash_table_entry.h"

namespace ENCRYPTO {

void swap(HashTableEntry& a, HashTableEntry& b) noexcept {
  std::swap(a.value_, b.value_);
  std::swap(a.global_id_, b.global_id_);
  std::swap(a.possible_addresses_, b.possible_addresses_);
  std::swap(a.current_function_id_, b.current_function_id_);
  std::swap(a.num_of_bins_, b.num_of_bins_);
  std::swap(a.num_of_hash_functions_, b.num_of_hash_functions_);
}

bool CuckooTable::Insert(std::uint64_t element) {
  elements_.push_back(element);
  return true;
}

bool CuckooTable::Insert(const std::vector<std::uint64_t>& elements) {
  elements_.insert(this->elements_.end(), elements.begin(), elements.end());
  return true;
};

void CuckooTable::SetRecursiveInsertionLimiter(std::size_t limiter) {
  recursion_limiter_ = limiter;
}

bool CuckooTable::Print() const {
  if (!mapped_) {
    std::cout << "Cuckoo hashing. The table is empty. "
                 "You must map elements to the table using MapElementsToTable() "
                 "before you print it.\n";
    return false;
  }
  std::cout << "Cuckoo hashing - table content "
               "(the format is \"[bin#] initial_element# element_value (function#)\"):\n";
  for (auto i = 0ull; i < hash_table_.size(); ++i) {
    const auto& entry = hash_table_.at(i);
    std::string id = entry.IsEmpty() ? "" : std::to_string(entry.GetGlobalID());
    std::string value = entry.IsEmpty() ? "" : std::to_string(entry.GetElement());
    std::string f = entry.IsEmpty() ? "" : std::to_string(entry.GetCurrentFunctinId());
    f = std::string("(" + f + ")");
    std::cout << "["<<i<<"] "<<id<<" "<<value<<" "<< f;
  }

  if (stash_.size() == 0) {
    std::cout << ", no stash";
  } else {
    std::cout << " stash has "<<stash_.size()<<" elements: ";
    for (auto i = 0ull; i < stash_.size(); ++i) {
      std::string delimiter = i == 0 ? "" : ", ";
      std::cout <<  delimiter<< stash_.at(i).GetGlobalID() << " " <<
                               stash_.at(i).GetElement();
    }
  }

  std::cout << std::endl;

  return true;
}

std::vector<uint64_t> CuckooTable::AsRawVector() const {
  std::vector<uint64_t> raw_table;
  raw_table.reserve(num_bins_);

  for (auto i = 0ull; i < num_bins_; ++i) {
    raw_table.push_back(hash_table_.at(i).GetElement() ^
                        static_cast<uint64_t>(hash_table_.at(i).GetCurrentFunctinId()));
  }

  return raw_table;
}

std::vector<std::size_t> CuckooTable::GetNumOfElementsInBins() const {
  std::vector<uint64_t> num_elements_in_bins(hash_table_.size(), 0);
  for (auto i = 0ull; i < hash_table_.size(); ++i) {
    if (!hash_table_.at(i).IsEmpty()) {
      ++num_elements_in_bins.at(i);
    }
  }
  return num_elements_in_bins;
}

CuckooTable::CuckooTable(double epsilon, std::size_t num_of_bins, std::size_t seed) {
  epsilon_ = epsilon;
  num_bins_ = num_of_bins;
  seed_ = seed;
  generator_.seed(seed_);
}

bool CuckooTable::AllocateTable() {
  if (num_bins_ == 0 && epsilon_ == 0.0f) {
    throw(
        std::runtime_error("You must set to a non-zero value "
                           "either the number of bins or epsilon "
                           "in the cuckoo hash table"));
  } else if (epsilon_ < 0.0f) {
    throw(std::runtime_error("Epsilon cannot be negative in the cuckoo hash table"));
  }

  if (epsilon_ > 0.0f) {
    num_bins_ = static_cast<uint64_t>((elements_.size() * epsilon_));
  }
  assert(num_bins_ > 0);
  hash_table_.resize(num_bins_);
  return true;
}

bool CuckooTable::MapElementsToTable() {
  assert(!mapped_);

  AllocateLUTs();
  GenerateLUTs();

  for (auto element_id = 0ull; element_id < elements_.size(); ++element_id) {
    HashTableEntry current_entry(elements_.at(element_id), element_id, num_of_hash_functions_,
                                 num_bins_);

    // find the new element's mappings and put them to the corresponding std::vector
    auto addresses = HashToPosition(elements_.at(element_id));
    current_entry.SetPossibleAddresses(std::move(addresses));
    current_entry.SetCurrentAddress(0);

    std::swap(current_entry, hash_table_.at(current_entry.GetCurrentAddress()));

    for (auto recursion_step = 0ull; !current_entry.IsEmpty(); ++recursion_step) {
      if (recursion_step > recursion_limiter_) {
        stash_.push_back(current_entry);
        break;
      } else {
        ++statistics_.recursive_remappings_counter_;
        current_entry.IterateFunctionNumber();
        current_entry.GetCurrentAddress();
        std::swap(current_entry, hash_table_.at(current_entry.GetCurrentAddress()));
      }
    }
  }

  mapped_ = true;

  return true;
}
}