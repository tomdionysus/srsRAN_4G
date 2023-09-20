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

#include <iostream>
#include <map>
#include <string>

#include "srsepc/hdr/hss/ue_store_csv.h"

using namespace std;

namespace srsepc {

ue_store_csv::ue_store_csv(std::string filename)
{
  _filename = filename;
}

ue_store_csv::~ue_store_csv() {}

uint ue_store_csv::init()
{
  // Open the CSV file
  std::ifstream file(_filename);
  if (!file.is_open()) {
    std::cerr << "ue_store_csv::init : Failed to open CSV file." << std::endl;
    return 1;
  }

  // Read and process each line of the CSV file
  std::string line;
  while (std::getline(file, line)) {
    // Skip lines starting with #
    if (line.empty() || line[0] == '#') {
      continue;
    }

    std::istringstream       ss(line);
    std::vector<std::string> tokens;
    std::string              token;

    // Split the line into tokens based on comma (',') delimiter
    while (std::getline(ss, token, ',')) {
      tokens.push_back(token);
    }

    if (tokens.size() != 10) {
      std::cerr << "ue_store_csv::init : Invalid line in CSV file: " << line << std::endl;
      continue;
    }

    // Parse and store data in hss_ue_ctx_t structure
    hss_ue_ctx_t user;
    user.name = tokens[0];
    user.algo = (tokens[1] == "xor") ? HSS_ALGO_XOR : HSS_ALGO_MILENAGE;
    user.imsi = std::stoull(tokens[2], nullptr, 10);

    // Parse and store the key, op, opc, amf, and sqn fields here
    if (tokens[3].size() != 32 || tokens[5].size() != 32 || tokens[6].size() != 4 || tokens[7].size() != 12) {
      std::cerr << "ue_store_csv::init : Invalid data format in CSV file: " << line << std::endl;
      continue;
    }

    for (int i = 0; i < 16; ++i) {
      std::string hexByte = tokens[3].substr(i * 2, 2);
      user.key[i]         = static_cast<uint8_t>(std::stoi(hexByte, nullptr, 16));
    }

    user.op_configured = (tokens[4] == "opc");

    for (int i = 0; i < 16; ++i) {
      std::string hexByte = tokens[5].substr(i * 2, 2);
      user.op[i]          = static_cast<uint8_t>(std::stoi(hexByte, nullptr, 16));
      user.opc[i]         = user.op[i];
    }

    for (int i = 0; i < 2; ++i) {
      std::string hexByte = tokens[6].substr(i * 2, 2);
      user.amf[i]         = static_cast<uint8_t>(std::stoi(hexByte, nullptr, 16));
    }

    for (int i = 0; i < 6; ++i) {
      std::string hexByte = tokens[7].substr(i * 2, 2);
      user.sqn[i]         = static_cast<uint8_t>(std::stoi(hexByte, nullptr, 16));
    }

    user.qci            = std::stoi(tokens[8]);
    user.static_ip_addr = tokens[9];

    user.store = this;

    // Add the user to the map with IMSI as the key
    _ue_subscriber[user.imsi] = user;
  }

  // Close the file
  file.close();

  return 0;
}

uint ue_store_csv::close()
{
  // Nothing to do
  return 0;
}

bool ue_store_csv::get_ue_ctx(uint64_t ssid, hss_ue_ctx_t* ctx)
{
  std::map<uint64_t, hss_ue_ctx_t>::iterator it;
  it = _ue_subscriber.find(ssid);
  if (it == _ue_subscriber.end())
    return false;
  *ctx = it->second;
  return true;
}

 bool ue_store_csv::set_sqn(uint64_t ssid, const uint8_t* sqn) 
 {
  // Do nothing for CSV UE DB.

  return true;
 }

 bool ue_store_csv::set_last_rand(uint64_t ssid, const uint8_t* last_rand)
 {
  // Do nothing for CSV UE DB.
  return true;
 }

} // namespace srsepc