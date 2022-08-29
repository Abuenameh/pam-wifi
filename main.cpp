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

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "process/process.hpp"

using namespace TinyProcessLib;

inline std::vector<std::string> split(const std::string &text, const std::string &delims)
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

inline std::string tolower(std::string s)
{
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c)
                 { return std::tolower(c); });
  return s;
}

/**
 * The main function, runs the identification and authentication
 * @param  pamh     The handle to interface directly with PAM
 * @param  flags    Flags passed on to us by PAM, XORed
 * @param  argc     Amount of rules in the PAM config (disregared)
 * @param  argv     Options defined in the PAM config
 * @param  auth_tok True if we should ask for a password too
 * @return          Returns a PAM return code
 */
auto check(pam_handle_t *pamh, int flags, int argc, const char **argv,
           bool auth_tok) -> int
{
  INIReader config("/lib64/security/pam-wifi/config.ini");
  openlog("pam_wifi", 0, LOG_AUTHPRIV);

  // Error out if we could not read the config file
  if (config.ParseError() != 0)
  {
    syslog(LOG_ERR, "Failed to parse the configuration file: %d",
           config.ParseError());
    return PAM_IGNORE;
  }

  std::string iface = config.GetString("core", "interface", "wlan0");
  std::string raw_bssids = config.GetString("core", "bssids", "");
  std::vector<std::string> bssids = split(raw_bssids, "\n");

  // Will contain the responses from PAM functions
  int pam_res = PAM_IGNORE;

  // Will contain PAM conversation structure
  struct pam_conv *conv = nullptr;
  const void **conv_ptr =
      const_cast<const void **>(reinterpret_cast<void **>(&conv));

  if ((pam_res = pam_get_item(pamh, PAM_CONV, conv_ptr)) != PAM_SUCCESS)
  {
    syslog(LOG_ERR, "Failed to acquire conversation");
    return pam_res;
  }

  // Get the username from PAM, needed to match correct face model
  char *username = nullptr;
  if ((pam_res = pam_get_user(pamh, const_cast<const char **>(&username),
                              nullptr)) != PAM_SUCCESS)
  {
    syslog(LOG_ERR, "Failed to get username");
    return pam_res;
  }

  std::ostringstream oss;
  Process bssid_proc("iw " + iface + " link", "", [&](const char *bytes, size_t n)
                     { oss << std::string{bytes, n}; });

  // Start the subprocess
  int status = bssid_proc.get_exit_status();

  if (status)
  {
    syslog(LOG_ERR, "Failure, unknown error %d", status);
    return PAM_IGNORE;
  }

  std::string out = split(oss.str(), "\n")[0];
  std::regex bssid_pattern("[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]");
  std::smatch bssid_match;
  std::string bssid;
  if (std::regex_search(out, bssid_match, bssid_pattern))
  {
    bssid = bssid_match[1];
  }
  else
  {
    syslog(LOG_ERR, "Unable to parse BSSID: %s", out.c_str());
    return PAM_IGNORE;
  }

  for (auto &auth_bssid : bssids)
  {
    if (tolower(bssid) == tolower(auth_bssid))
    {
      syslog(LOG_INFO, "Authorized WiFi network found");

      return PAM_SUCCESS;
    }
  }

  return PAM_IGNORE;
}

// Called by PAM when a user needs to be authenticated, for example by running
// the sudo command
PAM_EXTERN auto pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv) -> int
{
  return check(pamh, flags, argc, argv, false);
}

// Called by PAM when a session is started, such as by the su command
PAM_EXTERN auto pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv) -> int
{
  return check(pamh, flags, argc, argv, false);
}

// The functions below are required by PAM, but not needed in this module
PAM_EXTERN auto pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                 const char **argv) -> int
{
  return PAM_IGNORE;
}
PAM_EXTERN auto pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                     const char **argv) -> int
{
  return PAM_IGNORE;
}
PAM_EXTERN auto pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                 const char **argv) -> int
{
  return PAM_IGNORE;
}
PAM_EXTERN auto pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                               const char **argv) -> int
{
  return PAM_IGNORE;
}
