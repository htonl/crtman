#include "handle_request.h"

/*
 * @brief Handle the GetCACert Request
 *
 * @param [in] request The incoming request for crtman
 * @param [out] response The response to the request
 */
static CA_STATUS handle_get_ca_cert_req(const char *request, const char **response);

/*
 * @brief Handle the IssueCert Request
 *
 * @param [in] request The incoming request for crtman
 * @param [out] response The response to the request
 */
static CA_STATUS handle_issue_cert_req(const char *request, const char **response);

/*
 * @brief Handle the RevokeCert Request
 *
 * @param [in] request The incoming request for crtman
 * @param [out] response The response to the request
 */
static CA_STATUS handle_revoke_cert_req(const char *request, const char **response);

/*
 * @brief Handle the GetCRL Request
 *
 * @param [in] request The incoming request for crtman
 * @param [out] response The response to the request
 */
static CA_STATUS handle_get_crl_req(const char *request, const char **response);

/*
 * handle_request assumes the caller has authenticated the request
 */
CA_STATUS handle_request(const char *request, const char **response)
{
    CA_STATUS status = CA_OK;

    // Parse_request_into_JSON_OBJ(obj);
    // Parse_command_from_obj(obj, cmd);
    // switch (cmd)
    // {
    // case GetCACert:
    //      handle_get_ca_cert_req(obj, response);
    //      ...

    return status;
}


