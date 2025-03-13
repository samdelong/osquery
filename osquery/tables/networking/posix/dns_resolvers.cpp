/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <array>
#include <set>
#include <filesystem>

#include <netinet/in.h>

#include <resolv.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/networking/posix/utils.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>
#include <osquery/worker/logging/glog/glog_logger.h>

namespace osquery {
namespace tables {

QueryData genDNSResolversImpl(QueryContext& context, Logger& logger) {
  QueryData results;
  int id = 0;

  // The global structure is called "_res" and is of the semi-opaque type
  // struct __res_state from the same resolv.h. An application many communicate
  // with the resolver discovery, but we are interested in the default state.

  // Attempt to get resolvers from /etc/resolv.conf
  std::ifstream resolv_conf("/etc/resolv.conf");
    
  if (resolv_conf.is_open()) {
      std::string line;
      while (std::getline(resolv_conf, line)) {
          if (line.substr(0, 10) == "nameserver") {
              size_t pos = line.find_first_not_of(" \t", 10);
              if (pos != std::string::npos) {
                  std::string ip = line.substr(pos);
                  // Trim whitespace
                  ip.erase(ip.find_last_not_of(" \t\n\r") + 1);
                  if (ip != "127.0.0.53") { // Skip systemd-resolved stub listener
                      Row r;
                      r["id"] = id;
                      id++;
                      r["type"] = "nameserver";
                      r["address"] = ip;
                      r["netmask"] = "32";
                      results.push_back(r);
                  }
              }
          }
      }
      resolv_conf.close();

  }
  std::array<char, 128> buffer;
  std::unique_ptr<FILE, decltype(&pclose)> pipe(popen("which nmcli >/dev/null 2>&1 && nmcli dev show | grep 'IP4.DNS'", "r"), pclose);
  
  if (pipe) {
      while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
          std::string line(buffer.data());
          size_t pos = line.find(':');
          if (pos != std::string::npos) {
              std::string ip = line.substr(pos + 1);
              // Trim whitespace
              ip.erase(0, ip.find_first_not_of(" \t\n\r"));
              ip.erase(ip.find_last_not_of(" \t\n\r") + 1);
              Row r;
              r["id"] = id;
              id++;
              r["type"] = "nameserver";
              r["address"] = ip;
              r["netmask"] = "32";
              results.push_back(r);
          }
      }
  }

  return results;
}
QueryData genDNSResolversImpl2(QueryContext& context, Logger& logger) {
  QueryData results;

  // libresolv will populate a global structure with resolver information.
  if (res_init() == -1) {
    return {};
  }

  // The global structure is called "_res" and is of the semi-opaque type
  // struct __res_state from the same resolv.h. An application many communicate
  // with the resolver discovery, but we are interested in the default state.
  struct __res_state& rr = _res;
  if (rr.nscount > 0) {
    for (size_t i = 0; i < static_cast<size_t>(_res.nscount); i++) {
      Row r;
      r["id"] = INTEGER(i);
      r["type"] = "nameserver";
      r["address"] = ipAsString((const struct sockaddr*)&_res.nsaddr_list[i]);
      r["netmask"] = "32";
      // Options applies to every resolver.
      r["options"] = BIGINT(_res.options);
      r["pid_with_namespace"] = "0";
      results.push_back(r);
    }
  }

  if (_res.nsort > 0) {
    for (size_t i = 0; i < static_cast<size_t>(_res.nsort); i++) {
      Row r;
      r["id"] = INTEGER(i);
      r["type"] = "sortlist";
      r["address"] =
          ipAsString((const struct sockaddr*)&_res.sort_list[i].addr);
      r["netmask"] = INTEGER(_res.sort_list[i].mask);
      r["options"] = BIGINT(_res.options);
      r["pid_with_namespace"] = "0";
      results.push_back(r);
    }
  }

  for (size_t i = 0; i < MAXDNSRCH; i++) {
    if (_res.dnsrch[i] != nullptr) {
      Row r;
      r["id"] = INTEGER(i);
      r["type"] = "search";
      r["address"] = std::string(_res.dnsrch[i]);
      r["options"] = BIGINT(_res.options);
      r["pid_with_namespace"] = "0";
      results.push_back(r);
    }
  }

  res_close();
  return results;
}

QueryData genDNSResolvers(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(context, "dns_resolvers", genDNSResolversImpl);
  } else {
    GLOGLogger logger;
    return genDNSResolversImpl(context, logger);
  }
}
}
}
