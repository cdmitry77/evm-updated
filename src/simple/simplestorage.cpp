// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "eEVM/simple/simplestorage.h"

#include "eEVM/util.h"

#include <ostream>

namespace eevm
{
  SimpleStorage::SimpleStorage(const nlohmann::json& j)
  {
    for (auto it = j.cbegin(); it != j.cend(); it++)
      s.emplace(
        std::piecewise_construct,
        /* key */ std::forward_as_tuple(to_uint256(it.key())),
        /* value */ std::forward_as_tuple(to_uint256(it.value())));
  }

  void SimpleStorage::store(const uint256_t& key, const uint256_t& value)
  {
    s[key] = value;
  }

  uint256_t SimpleStorage::load(const uint256_t& key)
  {
    auto e = s.find(key);
    if (e == s.end())
      return 0;
    return e->second;
  }

  bool SimpleStorage::exists(const uint256_t& key)
  {
    return s.find(key) != s.end();
  }

  bool SimpleStorage::remove(const uint256_t& key)
  {
    auto e = s.find(key);
    if (e == s.end())
      return false;
    s.erase(e);
    return true;
  }

  bool SimpleStorage::operator==(const SimpleStorage& that) const
  {
    return s == that.s;
  }

  std::vector<uint8_t> SimpleStorage::toByteCode() const{
    std::vector<uint8_t> res;
    size_t cnt = 0;
    for (const auto& p : s)
    {
      res.reserve((cnt + 1) * 64);
      eevm::to_big_endian(p.first, res.data() + cnt*2 * 32);
      eevm::to_big_endian(p.second, res.data() + (cnt*2 + 1) * 32);
      ++cnt;
    }
    return res;
  }

  std::string SimpleStorage::to_hex_string_full(const uint256_t& v)
  {
    std::stringstream ss;
    ss << "0x" << std::setfill('0') << std::setw(64) << intx::hex(v);
    std::string res(ss.str());
    return res;
  }

  std::string SimpleStorage::saveToDB() {
    std::string res;
    size_t cnt = 0;
    res.reserve(s.size()*132);
    for (const auto& p : s)
    {
      res += to_hex_string_full(p.first);
      res += to_hex_string_full(p.second);
      ++cnt;
    }
    return res;
  }


  void SimpleStorage::loadFromDB(eevm::SimpleStorage& st, const std::string& data) {
    
    size_t cnt = 0;
    while (cnt < data.size()) {
      std::string cAddr(data.data() + 132 * cnt, 66);
      std::string cData(data.data() + 132 * cnt + 66, 66);
      
        ++cnt;
    }
    (void) st;
  }



  void to_json(nlohmann::json& j, const SimpleStorage& s)
  {
    j = nlohmann::json::object();

    for (const auto& p : s.s)
    {
      j[to_hex_string(p.first)] = to_hex_string(p.second);
    }
  }

  void from_json(const nlohmann::json& j, SimpleStorage& s)
  {
    for (decltype(auto) it = j.cbegin(); it != j.cend(); it++)
    {
      s.s.emplace(to_uint256(it.key()), to_uint256(it.value()));
    }
  }

  inline std::ostream& operator<<(std::ostream& os, const SimpleStorage& s)
  {
    os << nlohmann::json(s).dump(2);
    return os;
  }
} // namespace eevm
