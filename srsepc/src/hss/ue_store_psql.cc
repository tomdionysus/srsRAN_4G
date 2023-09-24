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

#include "srsepc/hdr/hss/ue_store_psql.h"

using namespace std;

namespace srsepc {

ue_store_psql::ue_store_psql(std::string host, std::string database, std::string username, std::string password)
{
  _host     = host;
  _database = database;
  _username = username;
  _password = password;
}

ue_store_psql::~ue_store_psql() {}

uint ue_store_psql::init()
{
  _conn =
      PQsetdbLogin(_host.c_str(), "5432", nullptr, nullptr, _database.c_str(), _username.c_str(), _password.c_str());
  if (PQstatus(_conn) != CONNECTION_OK) {
    std::cerr << "ue_store_psql::init : Connection to database failed: " << PQerrorMessage(_conn) << std::endl;
    PQfinish(_conn);
    return PQstatus(_conn);
  }
  return 0;
}

uint ue_store_psql::close()
{
  PQfinish(_conn);
  return 0;
}

bool ue_store_psql::get_ue_ctx(uint64_t ssid, hss_ue_ctx_t* ctx)
{
  // Assumption is failure
  bool success = false;

  // Build the query
  std::string query = "SELECT \"imsi\", \"name\", \"auth\", \"key_identifier\", \"op_type\", \"op_opc\", \"amf\", "
                      "\"sqn\", \"qci\", \"ip_alloc\" FROM \"ue_subscriber\" WHERE \"imsi\" = " +
                      std::to_string(ssid);

  // Perform the query
  PGresult* result = PQexec(_conn, query.c_str());

  // Check if the query execution was successful
  if (PQresultStatus(result) == PGRES_TUPLES_OK) {
    int num_rows = PQntuples(result);

    // Check if there is exactly one row
    if (num_rows == 1) {
      int num_fields = PQnfields(result);

      // There should be 10 fields
      if (num_fields == 10) {
        // Get IMSI
        ctx->imsi = strtoull(PQgetvalue(result, 0, 0), nullptr, 10);

        // Get Name
        ctx->name = PQgetvalue(result, 0, 1);

        // Get Auth Type
        const char* auth = PQgetvalue(result, 0, 2);
        if (strcmp("xor", auth) == 0) {
          ctx->algo = HSS_ALGO_XOR;
        } else if (strcmp("mil", auth) == 0) {
          ctx->algo = HSS_ALGO_MILENAGE;
        }

        char*          byteaHexStr;
        unsigned char* byteaData;
        size_t         length;

        // Get KI
        byteaHexStr = PQgetvalue(result, 0, 3);
        byteaData   = PQunescapeBytea((const unsigned char*)byteaHexStr, &length);
        memcpy(ctx->key, byteaData, 16);
        PQfreemem(byteaData);

        // Get OP / OPC Type
        const char* op_type = PQgetvalue(result, 0, 4);
        ctx->op_configured  = (strcmp("opc", op_type) == 0);

        // Get OP/OPC
        byteaHexStr = PQgetvalue(result, 0, 5);
        byteaData   = PQunescapeBytea((const unsigned char*)byteaHexStr, &length);
        memcpy(ctx->op_configured ? ctx->opc : ctx->op, byteaData, 16);
        PQfreemem(byteaData);

        // Get AMF
        byteaHexStr = PQgetvalue(result, 0, 6);
        byteaData   = PQunescapeBytea((const unsigned char*)byteaHexStr, &length);
        memcpy(ctx->amf, byteaData, 2);
        PQfreemem(byteaData);

        // Get SQN
        byteaHexStr = PQgetvalue(result, 0, 7);
        byteaData   = PQunescapeBytea((const unsigned char*)byteaHexStr, &length);
        memcpy(ctx->sqn, byteaData, 6);
        PQfreemem(byteaData);

        // Get QCI
        ctx->qci = atoi(PQgetvalue(result, 0, 8));

        // Get Assigned IP, or mark dynamic
        ctx->static_ip_addr = PQgetvalue(result, 0, 9);

        ctx->store = this;

        success = true;
      } else {
        std::cerr << "ue_store_psql::get_ue_ctx : Too many fields returned" << std::endl;
      }
    }
  } else {
    std::cerr << "ue_store_psql::get_ue_ctx : Query failed: " << PQerrorMessage(_conn) << std::endl;
  }

  // Free the result
  PQclear(result);

  return success;
}

bool ue_store_psql::set_sqn(uint64_t ssid, const uint8_t* sqn)
{
  // Do nothing for CSV UE DB.
  return true;
}

bool ue_store_psql::set_last_rand(uint64_t ssid, const uint8_t* last_rand)
{
  // Do nothing for CSV UE DB.
  return true;
}

bool ue_store_psql::get_imsi_from_ip(std::string ip, uint64_t* imsi)
{
  // TODO
  return false;
}

bool ue_store_psql::set_imsi_from_ip(std::string ip, uint64_t imsi)
{
  // TODO
  return false;
}

bool ue_store_psql::allocate_ip_from_imsi(std::string* ip, uint64_t imsi)
{
  // TODO
  return false;
}

} // namespace srsepc
