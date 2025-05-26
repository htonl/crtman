// ca_client.h

typedef struct CAClient CAClient;

// Connect to CA daemon (TLS)
int  ca_client_connect(const char *addr, int port, const char *cafile, CAClient **out);

// Close connection
void ca_client_close(CAClient *c);

// Fetch CA certificate
int  ca_client_get_ca_cert(CAClient *c, char **pem, char **err_msg);

// Issue a certificate
int  ca_client_issue_cert(CAClient *c,
                          const char *csr_pem,
                          int valid_days,
                          const char *profile,
                          char **cert_pem,
                          char **serial,
                          char **err_msg);

// Revoke a certificate
int  ca_client_revoke_cert(CAClient *c,
                           const char *serial,
                           int reason_code,
                           char **err_msg);

// Fetch current CRL
int  ca_client_get_crl(CAClient *c, char **crl_pem, char **err_msg);

// Error codes: <0 = local error, >0 = CA‐returned error_code

