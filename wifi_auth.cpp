#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <ostream>

#include <glob.h>
#include <libintl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdexcept>
#include <sys/signalfd.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <fstream>
#include <sstream>
#include <functional>
#include <future>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <tuple>
#include <vector>
#include <regex>

#include <INIReader.h>

#include "process/process.hpp"

using namespace TinyProcessLib;

std::vector<std::string> split(const std::string &text, const std::string &delims)
{
  std::vector<std::string> tokens;
  std::size_t start = text.find_first_not_of(delims), end = 0;

  while ((end = text.find_first_of(delims, start)) != std::string::npos)
  {
    tokens.push_back(text.substr(start, end - start));
    start = text.find_first_not_of(delims, end);
  }
  if (start != std::string::npos)
    tokens.push_back(text.substr(start));

  return tokens;
}

std::string tolower(std::string s)
{
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c)
                 { return std::tolower(c); });
  return s;
}

std::size_t replace_all(std::string& inout, std::string what, std::string with)
{
    std::size_t count{};
    for (std::string::size_type pos{};
         inout.npos != (pos = inout.find(what.data(), pos, what.length()));
         pos += with.length(), ++count) {
        inout.replace(pos, what.length(), with.data(), with.length());
    }
    return count;
}
 
std::size_t remove_all(std::string& inout, std::string what) {
    return replace_all(inout, what, "");
}

int main(int argc, char *argv[])
{
  INIReader config("/lib64/security/wifi/config.ini");
  openlog("wifi-auth", 0, LOG_AUTHPRIV);

  // Error out if we could not read the config file
  if (config.ParseError() != 0)
  {
    syslog(LOG_ERR, "Failed to parse the configuration file: %d",
           config.ParseError());
    exit(10);
  }

  std::string raw_bssids = config.GetString("authorized", "bssids", "");
  std::vector<std::string> bssids = split(raw_bssids, "\n");

  std::ostringstream oss;
  Process bssid_proc("nmcli -g bssid device wifi list", "", [&](const char *bytes, size_t n)
                     { oss << std::string{bytes, n}; });

  // Start the subprocess
  int status = bssid_proc.get_exit_status();

  if (status)
  {
    syslog(LOG_ERR, "Failure, nmcli returned %d", status);
    exit(11);
  }

  std::string bssid = oss.str();
  if (bssid.empty())
  {
    syslog(LOG_INFO, "Not connected to Wi-Fi network");
    exit(12);
  }
  bssid = split(bssid, "\n")[0];
  replace_all(bssid, "\\:", ":");

  for (auto &auth_bssid : bssids)
  {
    if (tolower(bssid) == tolower(auth_bssid))
    {
      exit(0);
    }
  }
  exit(13);
}