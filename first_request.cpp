#include "client.h"

using namespace std;

static int worker(Connect *r);
static int read_headers(Connect *r);
//======================================================================
static int client_(Connect *r)
{
    struct pollfd poll_fd;
    poll_fd.fd = r->servSocket;

    while (1)
    {
        time_t t = time(NULL);
        if (r->sock_timer == 0)
            r->sock_timer = t;
        if ((t - r->sock_timer) >= conf->Timeout)
        {
            fprintf(stderr, "<%s:%d> Timeout=%ld, %s\n", __func__, __LINE__, 
                            t - r->sock_timer, get_str_operation(r->operation));
            return -1;
        }

        if (r->io_status == WORK)
        {
            int ret = worker(r);
            if (ret < 0)
            {
                fprintf(stderr, "<%s:%d> Error worker()\n", __func__, __LINE__);
                return -1;
            }
            else if (ret == 1)
                break;
        }
        else
        {
            poll_fd.events = r->event;
            int ret = poll(&poll_fd, 1, conf->TimeoutPoll);
            if (ret == -1)
            {
                fprintf(stderr, "<%s:%d> Error poll(): %s\n", __func__, __LINE__, strerror(errno));
                return -1;
            }
            else if (ret == 0)
                continue;
            
            ret = worker(r);
            if (ret < 0)
            {
                fprintf(stderr, "<%s:%d> Error worker()\n", __func__, __LINE__);
                return -1;
            }
            else if (ret == 1)
            {
                fprintf(stderr, "<%s:%d> ------------\n", __func__, __LINE__);
                break;
            }
        }
    }

    return 0;
}
//======================================================================
static int worker(Connect *r)
{
    if (r->operation == SSL_CONNECT)
    {
        r->operation = SEND_REQUEST;
        r->event = POLLOUT;
        r->io_status = WORK;
    }
    else if (r->operation == SEND_REQUEST)
    {
        int wr = send_headers(r);
        if (wr > 0)
        {
            if ((r->req.len - r->req.i) == 0)
            {
                r->sock_timer = 0;
                r->operation = READ_RESP_HEADERS;
                r->event = POLLIN;
                r->cont_len = 0;
                r->resp.len = 0;
            }
            else
                r->sock_timer = 0;
        }
        else if (wr < 0)
        {
            if (wr == ERR_TRY_AGAIN)
                ;
            else
            {
                fprintf(stderr, "<%s:%d> Error send_headers()\n", __func__, __LINE__);
                return -1;
            }
        }
    }
    else if (r->operation == READ_RESP_HEADERS)
    {
        int ret = read_headers(r);
        if (ret < 0)
        {
            if (ret == ERR_TRY_AGAIN)
                ;
            else
            {
                fprintf(stderr, "<%s:%d> Error read_http_headers()\n", __func__, __LINE__);
                return -1;
            }
        }
        else if (ret > 0)
        {
            r->sock_timer = 0;
            r->operation = READ_ENTITY;
            r->event = POLLIN;
            r->cont_len = 0;
        }
        else
        {
            r->sock_timer = 0;
        }
    }
    else if (r->operation == READ_ENTITY)
    {
        char  buf[SIZE_BUF];
        int ret = read_from_server(r, buf, SIZE_BUF - 1);
        if (ret < 0)
        {
            if (ret == ERR_TRY_AGAIN)
                ;
            else
            {
                fprintf(stdout, "<%s:%d> Error read_from_server()=%d\n", __func__, __LINE__, ret);
                return -1;
            }
        }
        else if (ret == 0)
        {
            fprintf(stdout, "\n");
            return 1;
        }
        else
        {
             buf[ret] = 0;
             fprintf(stdout, "%s", buf);
             fflush(stdout);
             r->sock_timer = 0;
        }
    }
    return 0;
}
//======================================================================
static int read_headers(Connect *r)
{
    int len = SIZE_BUF - (r->resp.len + 1);
    if (len <= 0)
    {
        return -1;
    }

    int ret = read_from_server(r, r->resp.buf + r->resp.len, len);
    if (ret <= 0)
    {
        if (ret == ERR_TRY_AGAIN)
            return ERR_TRY_AGAIN;
        else
        {
            return -1;
        }
    }
    else
    {
        *(r->resp.buf + r->resp.len + ret) = 0;
        fprintf(stdout, "%s", r->resp.buf + r->resp.len);
        if (sscanf(r->resp.buf, "%*s %d %*s", &r->respStatus) == 1)
            return r->resp.len + ret;
        r->resp.len += ret;
    }

    return 0;
}
//======================================================================
int client(Connect *r)
{
    r->sock_timer = 0;
    r->err = 0;
    r->respStatus = 0;
    r->read_bytes = 0;
    r->req.i = 0;
    r->chunk.chunk = 0;

    if (conf->Protocol == HTTPS)
    {
        r->ssl = SSL_new(conf->ctx);
        if (!r->ssl)
        {
            fprintf(stderr, "<%s:%d> Error SSL_new()\n", __func__, __LINE__);
            return -1;
        }

        SSL_set_fd(r->ssl, r->servSocket);
        int ret = SSL_connect(r->ssl);
        if (ret < 1)
        {
            int err = SSL_get_error(r->ssl, ret);
            if (err == SSL_ERROR_WANT_WRITE)
            {
                r->operation = SSL_CONNECT;
                r->event = POLLOUT;
                r->io_status = POLL;
            }
            else if (err == SSL_ERROR_WANT_READ)
            {
                r->operation = SSL_CONNECT;
                r->event = POLLIN;
                r->io_status = POLL;
            }
            else
            {
                fprintf(stderr, "<%s:%d> Error SSL_connect()=%d\n", __func__, __LINE__, ret);
                SSL_shutdown(r->ssl);
                SSL_free(r->ssl);
                return -1;
            }
        }
        else
        {
            r->operation = SEND_REQUEST;
            r->event = POLLOUT;
            r->io_status = WORK;
        }
    }
    else
    {
        r->operation = SEND_REQUEST;
        r->event = POLLOUT;
        r->io_status = WORK;
    }

    int ret = client_(r);
    if (conf->Protocol == HTTPS)
    {
        SSL_shutdown(r->ssl);
        SSL_free(r->ssl);
    }

    return ret;
}
