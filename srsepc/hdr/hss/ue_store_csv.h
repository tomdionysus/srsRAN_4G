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

#ifndef SRSEPC_HSS_UE_STORE_CSV_H
#define SRSEPC_HSS_UE_STORE_CSV_H

#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "hss.h"

namespace srsepc {

class ue_store_csv : public ue_store
{
public:
  ue_store_csv(std::string filename);
  ~ue_store_csv();

  uint init();
  uint close();

  bool get_ue_ctx(uint64_t ssid, hss_ue_ctx_t* ctx);
  bool set_sqn(uint64_t ssid, const uint8_t* sqn);
  bool set_last_rand(uint64_t ssid, const uint8_t* last_rand);

  bool get_imsi_from_ip(std::string ip, uint64_t* imsi);
  bool set_imsi_from_ip(std::string ip, uint64_t imsi);
  bool allocate_ip_from_imsi(std::string* ip, uint64_t imsi);

private:
  std::string db_filename;

  std::map<uint64_t, std::shared_ptr<hss_ue_ctx_t> > m_imsi_to_ue_ctx;

  std::map<std::string, uint64_t> m_ip_to_imsi;

  srslog::basic_logger& m_logger = srslog::fetch_basic_logger("HSS");
};

} // namespace srsepc

#endif // SRSEPC_HSS_UE_STORE_CSV
