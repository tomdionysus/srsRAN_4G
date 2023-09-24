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
#include "srsepc/hdr/hss/hss.h"
#include "srsepc/hdr/hss/ue_store_csv.h"
#include "srsepc/hdr/hss/ue_store_mysql.h"
#include "srsepc/hdr/hss/ue_store_psql.h"
#include "srsran/common/security.h"
#include "srsran/common/string_helpers.h"
#include <arpa/inet.h>
#include <inttypes.h> // for printing uint64_t
#include <iomanip>
#include <sstream>
#include <stdlib.h> /* srand, rand */
#include <string>
#include <time.h>

namespace srsepc {

hss*            hss::m_instance    = NULL;
pthread_mutex_t hss_instance_mutex = PTHREAD_MUTEX_INITIALIZER;

hss::hss()
{
  return;
}

hss::~hss()
{
  return;
}

hss* hss::get_instance()
{
  pthread_mutex_lock(&hss_instance_mutex);
  if (NULL == m_instance) {
    m_instance = new hss();
  }
  pthread_mutex_unlock(&hss_instance_mutex);
  return (m_instance);
}

void hss::cleanup()
{
  pthread_mutex_lock(&hss_instance_mutex);
  if (NULL != m_instance) {
    delete m_instance;
    m_instance = NULL;
  }
  pthread_mutex_unlock(&hss_instance_mutex);
}

int hss::init(hss_args_t* hss_args)
{
  srand(time(NULL));

  mcc = hss_args->mcc;
  mnc = hss_args->mnc;

  if(hss_args->ue_store == "csv") {
    ue_ctx_store = new ue_store_csv(hss_args->db_file);
    m_logger.info("UE Store CSV: DB File %s", hss_args->db_file);

  } else if (hss_args->ue_store == "mysql") {
    ue_ctx_store = new ue_store_mysql(hss_args->db_host, hss_args->db_database, hss_args->db_username, hss_args->db_password);
    m_logger.info("UE Store MySQL: DB Host %s, DB User %s, Database %s", hss_args->db_host, hss_args->db_username, hss_args->db_database);

  } else if (hss_args->ue_store == "postgresql") {
    ue_ctx_store = new ue_store_psql(hss_args->db_host, hss_args->db_database, hss_args->db_username, hss_args->db_password);
    m_logger.info("UE Store PostgreSQL: DB Host %s, DB User %s, Database %s", hss_args->db_host, hss_args->db_username, hss_args->db_database);

  }
  
  if(ue_ctx_store->init() != 0) {
    srsran::console("Error initialising UE Store (%s).\n");
    exit(1);
  }

  m_logger.info("HSS Initialized. MCC: %d, MNC: %d", mcc, mnc);
  srsran::console("HSS Initialized.\n");
  return 0;
}

void hss::stop()
{
  ue_ctx_store->close();

  delete ue_ctx_store;
  return;
}

bool hss::gen_auth_info_answer(uint64_t imsi, uint8_t* k_asme, uint8_t* autn, uint8_t* rand, uint8_t* xres)
{
  m_logger.debug("Generating AUTH info answer");
  hss_ue_ctx_t ue_ctx_d; hss_ue_ctx_t* ue_ctx = &ue_ctx_d;

  if (!ue_ctx_store->get_ue_ctx(imsi, ue_ctx)) {
    srsran::console("User not found at HSS. IMSI: %015" PRIu64 "\n", imsi);
    m_logger.error("User not found at HSS. IMSI: %015" PRIu64 "", imsi);
    return false;
  }

  switch (ue_ctx->algo) {
    case HSS_ALGO_XOR:
      gen_auth_info_answer_xor(ue_ctx, k_asme, autn, rand, xres);
      break;
    case HSS_ALGO_MILENAGE:
      gen_auth_info_answer_milenage(ue_ctx, k_asme, autn, rand, xres);
      break;
  }

  //TODO
  increment_ue_sqn(ue_ctx);
  return true;
}

void hss::gen_auth_info_answer_milenage(hss_ue_ctx_t* ue_ctx,
                                        uint8_t*      k_asme,
                                        uint8_t*      autn,
                                        uint8_t*      rand,
                                        uint8_t*      xres)
{
  // Get K, AMF, OPC and SQN
  uint8_t* k   = ue_ctx->key;
  uint8_t* amf = ue_ctx->amf;
  uint8_t* opc = ue_ctx->opc;
  uint8_t* sqn = ue_ctx->sqn;

  // Temp variables
  uint8_t ck[16];
  uint8_t ik[16];
  uint8_t ak[6];
  uint8_t mac[8];

  gen_rand(rand);

  srsran::security_milenage_f2345(k, opc, rand, xres, ck, ik, ak);

  m_logger.debug(k, 16, "User Key : ");
  m_logger.debug(opc, 16, "User OPc : ");
  m_logger.debug(rand, 16, "User Rand : ");
  m_logger.debug(xres, 8, "User XRES: ");
  m_logger.debug(ck, 16, "User CK: ");
  m_logger.debug(ik, 16, "User IK: ");
  m_logger.debug(ak, 6, "User AK: ");

  srsran::security_milenage_f1(k, opc, rand, sqn, amf, mac);

  m_logger.debug(sqn, 6, "User SQN : ");
  m_logger.debug(mac, 8, "User MAC : ");

  uint8_t ak_xor_sqn[6];
  for (int i = 0; i < 6; i++) {
    ak_xor_sqn[i] = sqn[i] ^ ak[i];
  }
  // Generate K_asme
  srsran::security_generate_k_asme(ck, ik, ak_xor_sqn, mcc, mnc, k_asme);

  m_logger.debug("User MCC : %x  MNC : %x ", mcc, mnc);
  m_logger.debug(k_asme, 32, "User k_asme : ");

  // Generate AUTN (autn = sqn ^ ak |+| amf |+| mac)
  for (int i = 0; i < 6; i++) {
    autn[i] = sqn[i] ^ ak[i];
  }
  for (int i = 0; i < 2; i++) {
    autn[6 + i] = amf[i];
  }
  for (int i = 0; i < 8; i++) {
    autn[8 + i] = mac[i];
  }
  m_logger.debug(autn, 16, "User AUTN: ");

  // Set last RAND
  ue_ctx->set_last_rand(rand);
  return;
}

void hss::gen_auth_info_answer_xor(hss_ue_ctx_t* ue_ctx, uint8_t* k_asme, uint8_t* autn, uint8_t* rand, uint8_t* xres)
{
  // Get K, AMF, OPC and SQN
  uint8_t* k   = ue_ctx->key;
  uint8_t* amf = ue_ctx->amf;
  uint8_t* opc = ue_ctx->opc;
  uint8_t* sqn = ue_ctx->sqn;

  // Temp variables
  uint8_t xdout[16];
  uint8_t cdout[8];

  uint8_t ck[16];
  uint8_t ik[16];
  uint8_t ak[6];
  uint8_t mac[8];

  int i = 0;

  // Gen RAND
  gen_rand(rand);

  // Use RAND and K to compute RES, CK, IK and AK
  for (i = 0; i < 16; i++) {
    xdout[i] = k[i] ^ rand[i];
  }

  for (i = 0; i < 16; i++) {
    xres[i] = xdout[i];
    ck[i]   = xdout[(i + 1) % 16];
    ik[i]   = xdout[(i + 2) % 16];
  }
  for (i = 0; i < 6; i++) {
    ak[i] = xdout[i + 3];
  }

  m_logger.debug(k, 16, "User Key : ");
  m_logger.debug(opc, 16, "User OPc : ");
  m_logger.debug(rand, 16, "User Rand : ");
  m_logger.debug(xres, 8, "User XRES: ");
  m_logger.debug(ck, 16, "User CK: ");
  m_logger.debug(ik, 16, "User IK: ");
  m_logger.debug(ak, 6, "User AK: ");

  // Generate cdout
  for (i = 0; i < 6; i++) {
    cdout[i] = sqn[i];
  }
  for (i = 0; i < 2; i++) {
    cdout[6 + i] = amf[i];
  }

  // Generate MAC
  for (i = 0; i < 8; i++) {
    mac[i] = xdout[i] ^ cdout[i];
  }

  m_logger.debug(sqn, 6, "User SQN : ");
  m_logger.debug(mac, 8, "User MAC : ");

  // Generate AUTN (autn = sqn ^ ak |+| amf |+| mac)
  for (int i = 0; i < 6; i++) {
    autn[i] = sqn[i] ^ ak[i];
  }
  for (int i = 0; i < 2; i++) {
    autn[6 + i] = amf[i];
  }
  for (int i = 0; i < 8; i++) {
    autn[8 + i] = mac[i];
  }

  uint8_t ak_xor_sqn[6];
  for (int i = 0; i < 6; i++) {
    ak_xor_sqn[i] = sqn[i] ^ ak[i];
  }
  // Generate K_asme
  srsran::security_generate_k_asme(ck, ik, ak_xor_sqn, mcc, mnc, k_asme);

  m_logger.debug("User MCC : %x  MNC : %x ", mcc, mnc);
  m_logger.debug(k_asme, 32, "User k_asme : ");

  // Generate AUTN (autn = sqn ^ ak |+| amf |+| mac)
  for (int i = 0; i < 6; i++) {
    autn[i] = sqn[i] ^ ak[i];
  }
  for (int i = 0; i < 2; i++) {
    autn[6 + i] = amf[i];
  }
  for (int i = 0; i < 8; i++) {
    autn[8 + i] = mac[i];
  }

  m_logger.debug(autn, 8, "User AUTN: ");

  // Set last RAND
  ue_ctx->set_last_rand(rand);
  return;
}

bool hss::gen_update_loc_answer(uint64_t imsi, uint8_t* qci)
{
  hss_ue_ctx_t ue_ctx_d; hss_ue_ctx_t* ue_ctx = &ue_ctx_d;

  if (!ue_ctx_store->get_ue_ctx(imsi, ue_ctx)) {
    m_logger.info("User not found. IMSI: %015" PRIu64 "", imsi);
    srsran::console("User not found at HSS. IMSI: %015" PRIu64 "\n", imsi);
    return false;
  }

  m_logger.info("Found User %015" PRIu64 "", imsi);
  *qci = ue_ctx->qci;
  return true;
}

bool hss::resync_sqn(uint64_t imsi, uint8_t* auts)
{
  m_logger.debug("Re-syncing SQN");
  hss_ue_ctx_t ue_ctx_d; hss_ue_ctx_t* ue_ctx = &ue_ctx_d;

  if (!ue_ctx_store->get_ue_ctx(imsi, ue_ctx)) {
    srsran::console("User not found at HSS. IMSI: %015" PRIu64 "\n", imsi);
    m_logger.error("User not found at HSS. IMSI: %015" PRIu64 "", imsi);
    return false;
  }

  switch (ue_ctx->algo) {
    case HSS_ALGO_XOR:
      resync_sqn_xor(ue_ctx, auts);
      break;
    case HSS_ALGO_MILENAGE:
      resync_sqn_milenage(ue_ctx, auts);
      break;
  }

  increment_seq_after_resync(ue_ctx);
  return true;
}

void hss::resync_sqn_xor(hss_ue_ctx_t* ue_ctx, uint8_t* auts)
{
  m_logger.error("XOR SQN synchronization not supported yet");
  srsran::console("XOR SQNs synchronization not supported yet\n");
  return;
}

void hss::resync_sqn_milenage(hss_ue_ctx_t* ue_ctx, uint8_t* auts)
{
  // Get K, AMF, OPC and SQN
  uint8_t* k   = ue_ctx->key;
  uint8_t* amf = ue_ctx->amf;
  uint8_t* opc = ue_ctx->opc;
  uint8_t* sqn = ue_ctx->sqn;

  // Temp variables
  uint8_t last_rand[16];
  uint8_t ak[6];
  uint8_t mac_s[8];
  uint8_t sqn_ms_xor_ak[6];

  ue_ctx->get_last_rand(last_rand);

  for (int i = 0; i < 6; i++) {
    sqn_ms_xor_ak[i] = auts[i];
  }

  for (int i = 0; i < 8; i++) {
    mac_s[i] = auts[i + 6];
  }

  m_logger.debug(k, 16, "User Key : ");
  m_logger.debug(opc, 16, "User OPc : ");
  m_logger.debug(amf, 2, "User AMF : ");
  m_logger.debug(last_rand, 16, "User Last Rand : ");
  m_logger.debug(auts, 16, "AUTS : ");
  m_logger.debug(sqn_ms_xor_ak, 6, "SQN xor AK : ");
  m_logger.debug(mac_s, 8, "MAC : ");

  srsran::security_milenage_f5_star(k, opc, last_rand, ak);
  m_logger.debug(ak, 6, "Resynch AK : ");

  uint8_t sqn_ms[6];
  for (int i = 0; i < 6; i++) {
    sqn_ms[i] = sqn_ms_xor_ak[i] ^ ak[i];
  }
  m_logger.debug(sqn_ms, 6, "SQN MS : ");
  m_logger.debug(sqn, 6, "SQN HE : ");

  uint8_t mac_s_tmp[8];

  uint8_t dummy_amf[2] = {};

  srsran::security_milenage_f1_star(k, opc, last_rand, sqn_ms, dummy_amf, mac_s_tmp);
  m_logger.debug(mac_s_tmp, 8, "MAC calc : ");

  ue_ctx->set_sqn(sqn_ms);
  return;
}

void hss::increment_ue_sqn(hss_ue_ctx_t* ue_ctx)
{
  increment_sqn(ue_ctx->sqn, ue_ctx->sqn);
  m_logger.debug("Incremented SQN  -- IMSI: %015" PRIu64 "", ue_ctx->imsi);
  m_logger.debug(ue_ctx->sqn, 6, "SQN: ");
  ue_ctx->set_sqn(ue_ctx->sqn);
}

void hss::increment_sqn(uint8_t* sqn, uint8_t* next_sqn)
{
  // The following SQN incrementation function is implemented according to 3GPP TS 33.102 version 11.5.1 Annex C
  uint64_t seq;
  uint64_t ind;
  uint64_t sqn64;

  sqn64 = 0;

  for (int i = 0; i < 6; i++) {
    sqn64 |= (uint64_t)sqn[i] << (5 - i) * 8;
  }

  seq = sqn64 >> LTE_FDD_ENB_IND_HE_N_BITS;
  ind = sqn64 & LTE_FDD_ENB_IND_HE_MASK;

  uint64_t nextseq;
  uint64_t nextind;
  uint64_t nextsqn;

  nextseq = (seq + 1) % LTE_FDD_ENB_SEQ_HE_MAX_VALUE;
  nextind = (ind + 1) % LTE_FDD_ENB_IND_HE_MAX_VALUE;
  nextsqn = (nextseq << LTE_FDD_ENB_IND_HE_N_BITS) | nextind;

  for (int i = 0; i < 6; i++) {
    next_sqn[i] = (nextsqn >> (5 - i) * 8) & 0xFF;
  }
  return;
}

void hss::increment_seq_after_resync(hss_ue_ctx_t* ue_ctx)
{
  // This function only increment the SEQ part of the SQN for resynchronization purpose
  uint8_t* sqn = ue_ctx->sqn;

  uint64_t seq;
  uint64_t ind;
  uint64_t sqn64;

  sqn64 = 0;

  for (int i = 0; i < 6; i++) {
    sqn64 |= (uint64_t)sqn[i] << (5 - i) * 8;
  }

  seq = sqn64 >> LTE_FDD_ENB_IND_HE_N_BITS;
  ind = sqn64 & LTE_FDD_ENB_IND_HE_MASK;

  uint64_t nextseq;
  uint64_t nextsqn;

  nextseq = (seq + 1) % LTE_FDD_ENB_SEQ_HE_MAX_VALUE;
  nextsqn = (nextseq << LTE_FDD_ENB_IND_HE_N_BITS) | ind;

  for (int i = 0; i < 6; i++) {
    sqn[i] = (nextsqn >> (5 - i) * 8) & 0xFF;
  }

  ue_ctx->set_sqn(ue_ctx->sqn);
  return;
}

void hss::gen_rand(uint8_t rand_[16])
{
  for (int i = 0; i < 16; i++) {
    rand_[i] = rand() % 256; // Pulls on byte at a time. It's slow, but does not depend on RAND_MAX.
  }
  return;
}

ue_store_imsi_ip_interface* hss::get_ip_to_imsi() 
{
  return ue_ctx_store;
}

} // namespace srsepc
