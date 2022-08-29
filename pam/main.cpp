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

#include <cstring>

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

// Exit status codes returned by the compare process
enum WifiStatus : int {
  NO_AUTHORIZED_BSSIDS = 10,
  NMCLI_ERROR = 11,
  NOT_CONNECTED = 12,
  NO_AUTHORIZED_WIFI = 13
};

/**
 * Inspect the status code returned by the compare process
 * @param  status        The status code
 * @return               A PAM return code
 */
auto wifi_failure(int status)
    -> int
{
  // If the process has exited
  if (WIFEXITED(status))
  {
    // Get the status code returned
    status = WEXITSTATUS(status);

    switch (status)
    {
    case WifiStatus::NO_AUTHORIZED_BSSIDS:
      syslog(LOG_INFO, "Failure, no authorized BSSIDs known");
      break;
    case WifiStatus::NMCLI_ERROR:
      syslog(LOG_ERR, "Failure, nmcli error");
      break;
    case WifiStatus::NOT_CONNECTED:
      syslog(LOG_INFO, "Failure, not connected to Wi-Fi network");
      break;
    case WifiStatus::NO_AUTHORIZED_WIFI:
      syslog(LOG_INFO, "Failure, not connected to authorized Wi-Fi network");
      break;
    default:
      syslog(LOG_ERR, "Failure, unknown error %d", status);
    }
  }
  else if (WIFSIGNALED(status))
  {
    // We get the signal
    status = WTERMSIG(status);

    syslog(LOG_ERR, "Child killed by signal %s (%d)", strsignal(status),
           status);
  }

  // As this function is only called for failure status codes, tell PAM to ignore
  return PAM_IGNORE;
}

/**
 * Format the success message if the status is successful or log the error in
 * the other case
 * @param  status        Status code
 * @return          Returns the conversation function return code
 */
auto wifi_status(int status)
    -> int
{
  if (status != EXIT_SUCCESS)
  {
    return wifi_failure(status);
  }

      syslog(LOG_INFO, "Authorized Wi-Fi network found");

  return PAM_SUCCESS;
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
  openlog("pam_wifi", 0, LOG_AUTHPRIV);

  const char *const args[] = {"/lib64/security/wifi/wifi-auth", nullptr};
  pid_t child_pid;

  if (posix_spawnp(&child_pid, "/lib64/security/wifi/wifi-auth", nullptr, nullptr,
                   const_cast<char *const *>(args), nullptr) != 0)
  {
    syslog(LOG_ERR, "Can't spawn the wifi-auth process: %s (%d)", strerror(errno),
           errno);
    return PAM_SYSTEM_ERR;
  }

  int status;
  waitpid(child_pid, &status, 0);

  return wifi_status(status);
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
