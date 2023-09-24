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

/******************************************************************************
 * File:        hss.h
 * Description: Top-level HSS class. Creates and links all
 *              interfaces and helpers.
 *****************************************************************************/

#ifndef SRSEPC_HSS_H
#define SRSEPC_HSS_H

#include "srsran/common/buffer_pool.h"
#include "srsran/common/standard_streams.h"
#include "srsran/interfaces/epc_interfaces.h"
#include "srsran/srslog/srslog.h"

#include "ue_store.h"

#include <cstddef>

#include <map>

#define LTE_FDD_ENB_IND_HE_N_BITS 5
#define LTE_FDD_ENB_IND_HE_MASK 0x1FUL
#define LTE_FDD_ENB_IND_HE_MAX_VALUE 31
#define LTE_FDD_ENB_SEQ_HE_MAX_VALUE 0x07FFFFFFFFFFUL

namespace srsepc {

struct hss_args_t {
  std::string db_file;
  std::string ue_store;
  std::string db_host;
  std::string db_username;
  std::string db_password;
  std::string db_database;
  uint16_t    mcc;
  uint16_t    mnc;
};

class hss : public hss_interface_nas
{
public:
  static hss* get_instance(void);
  static void cleanup(void);
  int         init(hss_args_t* hss_args);
  void        stop(void);

  virtual bool gen_auth_info_answer(uint64_t imsi, uint8_t* k_asme, uint8_t* autn, uint8_t* rand, uint8_t* xres);
  virtual bool gen_update_loc_answer(uint64_t imsi, uint8_t* qci);

  virtual bool resync_sqn(uint64_t imsi, uint8_t* auts);

  virtual ue_store_imsi_ip_interface* get_ip_to_imsi();

private:
  hss();
  virtual ~hss();
  static hss* m_instance;

  void gen_rand(uint8_t rand_[16]);

  void gen_auth_info_answer_milenage(hss_ue_ctx_t* ue_ctx, uint8_t* k_asme, uint8_t* autn, uint8_t* rand, uint8_t* xres);
  void gen_auth_info_answer_xor(hss_ue_ctx_t* ue_ctx, uint8_t* k_asme, uint8_t* autn, uint8_t* rand, uint8_t* xres);

  void resync_sqn_milenage(hss_ue_ctx_t* ue_ctx, uint8_t* auts);
  void resync_sqn_xor(hss_ue_ctx_t* ue_ctx, uint8_t* auts);

  void get_uint_vec_from_hex_str(const std::string& key_str, uint8_t* key, uint len);

  void increment_ue_sqn(hss_ue_ctx_t* ue_ctx);
  void increment_seq_after_resync(hss_ue_ctx_t* ue_ctx);
  void increment_sqn(uint8_t* sqn, uint8_t* next_sqn);

  bool set_auth_algo(std::string auth_algo);
  bool read_db_file(std::string db_file);
  bool write_db_file(std::string db_file);

  std::string hex_string(uint8_t* hex, int size);

  std::string db_file;

  /*Logs*/
  srslog::basic_logger& m_logger = srslog::fetch_basic_logger("HSS");

  uint16_t mcc;
  uint16_t mnc;

  ue_store* ue_ctx_store;
};
} // namespace srsepc
#endif // SRSEPC_HSS_H
