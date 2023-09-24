/**
 * Copyright 2013-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#ifndef SRSEPC_HSS_UE_STORE_H
#define SRSEPC_HSS_UE_STORE_H

#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "srsran/interfaces/epc_interfaces.h"

namespace srsepc {

enum hss_auth_algo { HSS_ALGO_XOR, HSS_ALGO_MILENAGE };

class ue_store;

struct hss_ue_ctx_t {
  // Members
  std::string        name;
  uint64_t           imsi;
  enum hss_auth_algo algo;
  uint8_t            key[16];
  bool               op_configured;
  uint8_t            op[16];
  uint8_t            opc[16];
  uint8_t            amf[2];
  uint8_t            sqn[6];
  uint16_t           qci;
  uint8_t            last_rand[16];
  std::string        static_ip_addr;

  ue_store* store;

  // Helper getters/setters
  void set_sqn(const uint8_t* sqn_);
  void set_last_rand(const uint8_t* rand_);
  void get_last_rand(uint8_t* rand_);
};

#define SRSEPC_HSS_UE_STORE_CLAMP(a, b) (a < b ? a : b)

class ue_store : public ue_store_imsi_ip_interface
{
public:
  virtual ~ue_store(){};

  virtual uint init()  = 0;
  virtual uint close() = 0;

  virtual bool get_ue_ctx(uint64_t ssid, hss_ue_ctx_t* ctx)           = 0;
  virtual bool set_sqn(uint64_t ssid, const uint8_t* sqn)             = 0;
  virtual bool set_last_rand(uint64_t ssid, const uint8_t* last_rand) = 0;

  virtual bool get_imsi_from_ip(std::string ip, uint64_t* imsi)      = 0;
  virtual bool set_imsi_from_ip(std::string ip, uint64_t imsi)       = 0;
  virtual bool allocate_ip_from_imsi(std::string* ip, uint64_t imsi) = 0;
};

inline void hss_ue_ctx_t::set_sqn(const uint8_t* sqn_)
{
  memcpy(sqn, sqn_, 6);

  if (store) {
    store->set_sqn(imsi, sqn_);
  }
}

inline void hss_ue_ctx_t::set_last_rand(const uint8_t* last_rand_)
{
  memcpy(last_rand, last_rand_, 16);

  if (store) {
    store->set_last_rand(imsi, last_rand_);
  }
}

inline void hss_ue_ctx_t::get_last_rand(uint8_t* last_rand_)
{
  memcpy(last_rand_, last_rand, 16);
}

} // namespace srsepc

#endif // SRSEPC_HSS_UE_STORE
