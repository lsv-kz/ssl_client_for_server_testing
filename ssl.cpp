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
//======================================================================
int ssl_read(Connect *req, char *buf, int len)
{
    int ret = SSL_read(req->ssl, buf, len);
    if (ret <= 0)
    {
        req->ssl_err = SSL_get_error(req->ssl, ret);
        if (req->ssl_err == SSL_ERROR_ZERO_RETURN)
        {
            return 0;
        }
        else if (req->ssl_err == SSL_ERROR_WANT_READ)
        {
            req->ssl_err = 0;
            return ERR_TRY_AGAIN;
        }
        else if (req->ssl_err == SSL_ERROR_WANT_WRITE)
        {
            fprintf(stderr, "<%s:%d> ??? Error SSL_read(): SSL_ERROR_WANT_WRITE\n", __func__, __LINE__);
            req->ssl_err = 0;
            return ERR_TRY_AGAIN;
        }
        else
        {
            fprintf(stderr, "<%s:%d> Error SSL_read()=%d: %s\n", __func__, __LINE__, ret, ssl_strerror(req->ssl_err));
            return -1;
        }
    }
    else
        return ret;
}
//======================================================================
int ssl_write(Connect *req, const char *buf, int len)
{
    int ret = SSL_write(req->ssl, buf, len);
    if (ret <= 0)
    {
        req->ssl_err = SSL_get_error(req->ssl, ret);
        if (req->ssl_err == SSL_ERROR_WANT_WRITE)
        {
            req->ssl_err = 0;
            return ERR_TRY_AGAIN;
        }
        else if (req->ssl_err == SSL_ERROR_WANT_READ)
        {
            fprintf(stderr, "<%s:%d> ??? Error SSL_write(): %s, op=%s\n", __func__, __LINE__, ssl_strerror(req->ssl_err), get_str_operation(req->operation));
            req->ssl_err = 0;
            return ERR_TRY_AGAIN;
        }
        fprintf(stderr, "<%s:%d> Error SSL_write()=%d: %s, errno=%d\n", __func__, __LINE__, ret, ssl_strerror(req->ssl_err), errno);
        return -1;
    }
    else
        return ret;
}
