#include "client.h"

using namespace std;

void get_time(char *s, int size);
//======================================================================
int read_line(FILE *f, char *s, int size)
{
    char *p = s;
    int ch, len = 0, wr = 1;

    while (((ch = getc(f)) != EOF) && (len < size))
    {
        if (ch == '\n')
        {
            *p = 0;
            if (wr == 0)
            {
                wr = 1;
                continue;
            }
            return len;
        }
        else if (wr == 0)
            continue;
        else if (ch == '#')
        {
            wr = 0;
        }
        else if (ch != '\r')
        {
            *(p++) = (char)ch;
            ++len;
        }
    }
    *p = 0;

    return len;
}
//======================================================================
int read_req_file_(FILE *f, char *req, int size)
{
    *req = 0;
    char *p = req;
    int len = 0, read_startline = 0;

    while (len < size)
    {
        int n = read_line(f, p, size - len);
        if (n > 0)
        {
            len += n;
            int m = strlen(end_line);
            if ((len + m) < size)
            {
                if (read_startline == 0)
                {
                    if (sscanf(p, "%15s %1023s %*s", Method, Uri) != 2)
                        return -4;
                    read_startline = 1;
                }
                else
                {
                    if (strstr_case(p, "Connection"))
                    {
                        if (strstr_case(p + 11, "close"))
                            connKeepAlive = 0;
                        else
                            connKeepAlive = 1;
                    }
                    else if (strstr_case(p, "Host:"))
                    {
                        if (sscanf(p, "Host: %127s", Host) != 1)
                        {
                            fprintf(stderr, "Error: [%s]\n", p);
                            return -1;
                        }
                    }
                }

                strcat(p, end_line);
                len += m;
                p += (n + m);
            }
            else
                return -1;
        }
        else if (n == 0)
        {
            if (feof(f))
                return len;

            if (read_startline == 0)
            {
                int m = strlen(end_line);
                if ((len + m) < size)
                {
                    memcpy(p, end_line, m + 1);
                    len += m;
                    p += m;
                }
                else
                    return -3;
            }
            else
            {
                int m = strlen(end_line);
                if ((len + m) < size)
                {
                    memcpy(p, end_line, m + 1);
                    len += m;
                    p += m;
                    if (strcmp(Method, "POST"))
                        return len;
                    else
                    {
                        int ret;
                        while (len < size)
                        {
                            if ((ret = fread(p, 1, size - len - 1, f)) <= 0)
                                return len;
                            len += ret;
                            p += ret;
                            *p = 0;
                        }
                        *p = 0;
                        if (feof(f))
                            return len;
                        else
                            return -1;
                    }
                }
            }
        }
        else
            return n;
    }
    
    if (feof(f))
        return len;
    return -1;
}
//======================================================================
int read_req_file(const char *path, char *req, int size)
{
    FILE *f = fopen(path, "r");
    if (!f)
    {
        fprintf(stderr, " Error open request file(%s): %s\n", path, strerror(errno));
        return -1;
    }

    int n = read_req_file_(f, req, size);
    if (n <= 0)
    {
        fprintf(stderr, "<%s> Error read_req_file()=%d\n", __func__, n);
        fclose(f);
        return -1;
    }

    fclose(f);
    return n;
}
//======================================================================
int write_to_server(Connect *req, const char *buf, int len)
{
    if (conf->Protocol == HTTPS)
    {
        int ret = SSL_write(req->ssl, buf, len);
        if (ret <= 0)
        {
            req->ssl_err = SSL_get_error(req->ssl, ret);
            if ((req->ssl_err == SSL_ERROR_WANT_WRITE) || (req->ssl_err == SSL_ERROR_WANT_READ)/* || (errno == EAGAIN)*/)
            {
                req->ssl_err = 0;
                return ERR_TRY_AGAIN;
            }
            fprintf(stderr, "<%s:%d> Error SSL_write()=%d: %s, errno=%d\n", __func__, __LINE__, ret, ssl_strerror(req->ssl_err), errno);
            return -1;
        }
        else
            return ret;
    }
    else
    {
        if (len == 0)
        {
            fprintf(stderr, "<%s:%d:%d:%d> Error len=0\n", __func__, __LINE__, req->num_conn, req->num_req);
            return -1;
        }
        int ret = send(req->servSocket, buf, len, 0);
        if (ret == -1)
        {
            fprintf(stderr, "<%s:%d:%d:%d> Error send(): %s\n", __func__, __LINE__, req->num_conn, req->num_req, strerror(errno));
            if (errno == EAGAIN)
                return ERR_TRY_AGAIN;
            else 
                return -1;
        }
        else
            return  ret;
    }
}
//======================================================================
int read_from_server(Connect *req, char *buf, int len)
{
    if (conf->Protocol == HTTPS)
    {
        int ret = SSL_read(req->ssl, buf, len);
        if (ret <= 0)
        {
            req->ssl_err = SSL_get_error(req->ssl, ret);
            if (req->ssl_err == SSL_ERROR_ZERO_RETURN)
            {
                //fprintf(stderr, "<%s:%d> Error SSL_read(): SSL_ERROR_ZERO_RETURN\n", __func__, __LINE__);
                return 0;
            }
            else if (req->ssl_err == SSL_ERROR_WANT_READ)
            {
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
    else
    {
        if (len == 0)
        {
            fprintf(stderr, "<%s:%d:%d:%d> len=0\n", 
                        __func__, __LINE__, req->num_conn, req->num_req);
            return 0;
        }
    
        int ret = recv(req->servSocket, buf, len, 0);
        if (ret == -1)
        {
            if (errno == EAGAIN)
                return ERR_TRY_AGAIN;
            else
            {
                fprintf(stderr, "<%s:%d:%d:%d> Error recv(): %s\n", __func__, __LINE__, req->num_conn, req->num_req, strerror(errno));
                return -1;
            }
        }
        else
            return  ret;
    }
}
//======================================================================
int find_empty_line(Connect *req)
{
    char *pCR, *pLF;
    while (req->resp.lenTail > 0)
    {
        int i = 0, len_line = 0;
        pCR = pLF = NULL;
        while (i < req->resp.lenTail)
        {
            char ch = *(req->resp.p_newline + i);
            if (ch == '\r')// found CR
            {
                if (i == (req->resp.lenTail - 1))
                    return 0;
                if (pCR)
                    return -1;
                pCR = req->resp.p_newline + i;
            }
            else if (ch == '\n')// found LF
            {
                pLF = req->resp.p_newline + i;
                if ((pCR) && ((pLF - pCR) != 1))
                    return -1;
                i++;
                break;
            }
            else
                len_line++;
            i++;
        }

        if (pLF) // found end of line '\n'
        {
            if (pCR == NULL)
                *pLF = 0;
            else
                *pCR = 0;

            if (len_line == 0)
            {
                req->resp.lenTail -= i;
                if (req->resp.lenTail > 0)
                    req->resp.ptr = pLF + 1;
                else
                    req->resp.ptr = NULL;
                return 1;
            }

//fprintf(stderr, "[>%s]\n", req->resp.p_newline);

            if (!strlcmp_case(req->resp.p_newline, "HTTP/", 5))
            {
                req->respStatus = atoi(req->resp.p_newline + 9);
            }
            else if (memchr(req->resp.p_newline, ':', len_line))
            {
                int n = parse_headers(req, req->resp.p_newline);
                if (n < 0)
                    return n;
            }
            else
            {
                return -1;
            }

            req->resp.lenTail -= i;
            req->resp.p_newline = pLF + 1;
        }
        else if (pCR && (!pLF))
            return -1;
        else
            break;
    }

    return 0;
}
//======================================================================
int read_http_headers(Connect *r)
{
    int len = SIZE_BUF - r->resp.len - 1;
    if (len <= 0)
    {
        fprintf(stderr, "<%s:%d:%d:%d> Error: empty line not found\n", __func__, __LINE__, r->num_conn, r->num_req);
        return -1;
    }

    int ret = read_from_server(r, r->resp.buf + r->resp.len, len);
    if (ret < 0)
    {
        if (ret == ERR_TRY_AGAIN)
            return ERR_TRY_AGAIN;
        return -1;
    }
    else if (ret == 0)
    {
        fprintf(stderr, "<%s:%d:%d:%d> Error server hung up\n", __func__, __LINE__, r->num_conn, r->num_req);
        return -1;
    }

    r->resp.lenTail += ret;
    r->resp.len += ret;
    r->resp.buf[r->resp.len] = 0;

    ret = find_empty_line(r);
    if (ret == 1) // empty line found
    {
        return 1;
    }
    else if (ret < 0) // error
    {
        fprintf(stderr, "<%s:%d> Error find_empty_line()=%d\n", __func__, __LINE__, ret);
        return -1;
    }

    return 0;
}
