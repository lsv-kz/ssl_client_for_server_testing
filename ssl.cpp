#include "client.h"

using namespace std;

//======================================================================
const char *ssl_strerror(int err)
{
    switch (err)
    {
        case SSL_ERROR_NONE:
            return "SSL_ERROR_NONE";
        case SSL_ERROR_SSL:
            return "SSL_ERROR_SSL";
        case SSL_ERROR_WANT_READ:
            return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE:
            return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_WANT_X509_LOOKUP:
            return "SSL_ERROR_WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL:
            return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_ZERO_RETURN:
            return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_WANT_CONNECT:
            return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT:
            return "SSL_ERROR_WANT_ACCEPT";
    }
    
    return "?";
}
//======================================================================
SSL_CTX *InitCTX()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    //SSL_library_init();
    //OpenSSL_add_all_algorithms();
    //SSL_load_error_strings();

    method = TLS_client_method();
    //method = TLSv1_2_client_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    return ctx;
}
