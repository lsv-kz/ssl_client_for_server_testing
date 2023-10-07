#include "client.h"

using namespace std;
//======================================================================
void std_in(char *s, int len)
{
    char ch;
    
    while ((ch = getchar()) != '\n' && (len - 1))
    {
        *s++ = ch;
        len--;
    }
    *s = '\0';
    if (ch != '\n')
        while ((ch = getchar()) != '\n');
}
//======================================================================
int strcmp_case(const char *s1, const char *s2)
{
    char c1, c2;
    
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;

    for (; ; ++s1, ++s2)
    {
        c1 = *s1;
        c2 = *s2;
        if (!c1 && !c2) return 0;
        if (!c1) return -1;
        if (!c2) return 1;
        
        c1 += (c1 >= 'A') && (c1 <= 'Z') ? ('a' - 'A') : 0;
        c2 += (c2 >= 'A') && (c2 <= 'Z') ? ('a' - 'A') : 0;
        
        if (c1 > c2) return 1;
        if (c1 < c2) return -1;
    }

    return 0;
}
//======================================================================
const char *strstr_case(const char *s1, const char *s2)
{
    const char *p1, *p2;
    char c1, c2;
    
    if (!s1 || !s2) return NULL;
    if (*s2 == 0) return s1;

    for (; ; ++s1)
    {
        c1 = *s1;
        if (!c1) break;
        c2 = *s2;
        c1 += (c1 >= 'A') && (c1 <= 'Z') ? ('a' - 'A') : 0;
        c2 += (c2 >= 'A') && (c2 <= 'Z') ? ('a' - 'A') : 0;
        if (c1 == c2)
        {
            p1 = s1;
            p2 = s2;
            ++s1;
            ++p2;

            for (; ; ++s1, ++p2)
            {
                c2 = *p2;
                if (!c2) return p1;
                
                c1 = *s1;
                if (!c1) return NULL;

                c1 += (c1 >= 'A') && (c1 <= 'Z') ? ('a' - 'A') : 0;
                c2 += (c2 >= 'A') && (c2 <= 'Z') ? ('a' - 'A') : 0;
                if (c1 != c2)
                    break;
            }
        }
    }

    return NULL;
}
//======================================================================
int strlcmp_case(const char *s1, const char *s2, int len)
{
    char c1, c2;

    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;

    int diff = ('a' - 'A');

    for (; len > 0; --len, ++s1, ++s2)
    {
        c1 = *s1;
        c2 = *s2;
        if (!c1 && !c2) return 0;

        c1 += (c1 >= 'A') && (c1 <= 'Z') ? diff : 0;
        c2 += (c2 >= 'A') && (c2 <= 'Z') ? diff : 0;

        if (c1 != c2) return (c1 - c2);
    }

    return 0;
}
//======================================================================
int parse_headers(Connect *r, char *pName)
{
    int n;
    char *pVal, *p;

    if (!(p = strchr(pName, ':')))
        return -1;
    *p = 0;

    n = strspn(p + 1, "\x20");
    pVal = p + 1 + n;
    
    if (!strcmp_case(pName, "connection"))
    {
        if (strstr_case(pVal, "keep-alive"))
            r->connKeepAlive = 1;
        else
            r->connKeepAlive = 0;
    }
    else if (!strcmp_case(pName, "content-length"))
    {
        sscanf(pVal, "%lld", &r->cont_len);
        r->chunk.chunk = 0;
    }
    else if (!strcmp_case(pName, "server"))
    {
        snprintf(r->server, sizeof(r->server), "%s", pVal);
    }
    else if (!strcmp_case(pName, "Transfer-Encoding"))
    {
        if (strstr_case(pVal, "chunked"))
            r->chunk.chunk = 1;
    }

    return 0;
}
//======================================================================
int create_log_file()
{
    int flog_err = open("logs/error.log", O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); // O_APPEND O_TRUNC   
    if (flog_err == -1)
    {
        fprintf(stderr, "<%s:%d> Error create log_err: %s\n", __func__, __LINE__, strerror(errno));
        exit(1);
    }

    dup2(flog_err, STDERR_FILENO);
    return flog_err;
}
//======================================================================
int get_size_chunk(Connect *r)
{
    r->chunk.size = -1;
    char *p = (char*)memchr(r->resp.ptr, '\n', r->resp.len);
    if (!p)
        return ERR_TRY_AGAIN;

    int n = p - r->resp.ptr + 1;
    if (n > 8)
        return -1;

    if (sscanf(r->resp.ptr, "%lx", &r->chunk.size) == 1)
    {
        r->resp.ptr += n;
        r->resp.len -= n;
        return r->chunk.size;
    }
    else
        return -1;
}
//======================================================================
const char *get_str_operation(OPERATION_TYPE n)
{
    switch (n)
    {
        case CONNECT:
            return "CONNECT";
        case SSL_CONNECT:
            return "SSL_CONNECT";
        case SEND_REQUEST:
            return "SEND_REQUEST";
        case READ_RESP_HEADERS:
            return "READ_RESP_HEADERS";
        case READ_ENTITY:
            return "READ_ENTITY";
    }

    return "?";
}
//======================================================================
void hex_dump_stderr(const void *p, int n)
{
    if (!p)
    {
        fprintf(stderr, "<%s>------------------ p=%p -------------------\n", __func__, p);
        return;
    }

    int count, addr = 0, col;
    const unsigned char *buf = (unsigned char *)p;
    char str[18];

    for(count = 0; count < n;)
    {
        fprintf(stderr, "%08X  ", addr);
        for(col = 0, addr = addr + 0x10; (count < n) && (col < 16); count++, col++)
        {
            if (col == 8) fprintf(stderr, " ");
            fprintf(stderr, "%02X ", *(buf+count));
            str[col] = (*(buf + count) >= 32 && *(buf + count) < 127) ? *(buf + count) : '.';
        }
        str[col] = 0;
        if (col <= 8) fprintf(stderr, " ");
        fprintf(stderr, "%*s  %s\n",(16 - (col)) * 3, "", str);
    }
    fprintf(stderr, "-------------------------------------------------\n");
}
//======================================================================
void hex_dump_stderr(const char *s, int line, const void *p, int n)
{
    if (!p)
    {
        fprintf(stderr, "<%s:%d>------------------ p=%p -------------------\n", s, line, p);
        return;
    }

    int count, addr = 0, col;
    unsigned char *buf = (unsigned char*)p;
    char str[18];
    fprintf(stderr, "<%s:%d>--------------- HEX ---------------\n", s, line);
    for(count = 0; count < n;)
    {
        fprintf(stderr, "%08X  ", addr);
        for(col = 0, addr = addr + 0x10; (count < n) && (col < 16); count++, col++)
        {
            if (col == 8) fprintf(stderr, " ");
            fprintf(stderr, "%02X ", *(buf+count));
            str[col] = (*(buf + count) >= 32 && *(buf + count) < 127) ? *(buf + count) : '.';
        }
        str[col] = 0;
        if (col <= 8) fprintf(stderr, " ");
        fprintf(stderr, "%*s  %s\n",(16 - (col)) * 3, "", str);
    }
    
    fprintf(stderr, "--------------------------------------\n");
}
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
        return ssl_write(req, buf, len);
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
        return ssl_read(req, buf, len);
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
//======================================================================
int send_headers(Connect *r)
{
    int wr = write_to_server(r, r->req.ptr + r->req.i, r->req.len - r->req.i);
    if (wr < 0)
    {
        if (wr == ERR_TRY_AGAIN)
            return ERR_TRY_AGAIN;
        else
            return -1;
    }
    else if (wr > 0)
    {
        r->req.i += wr;
    }

    return wr;
}
//======================================================================
int chunk(Connect *r)
{
    if (!r->resp.ptr || !r->resp.len)
    {
        r->resp.len = 0;
        r->resp.ptr = r->resp.buf;
        r->chunk.size = -1;
        return 0;
    }

    while (1)
    {
        r->chunk.size = get_size_chunk(r);
        if (r->chunk.size > 0)
        {
            if (r->resp.len > (r->chunk.size + 2))
            {
                r->resp.ptr += (r->chunk.size + 2);
                r->resp.len -= (r->chunk.size + 2);
                continue;
            }
            else if (r->resp.len == (r->chunk.size + 2))
            {
                r->resp.len = 0;
                r->resp.ptr = r->resp.buf;
                r->chunk.size = -1;
                break;
            }
            else // r->resp.len < (r->chunk.size + 2)
            {
                r->chunk.size -= (r->resp.len - 2);
                r->resp.len = 0;
                break;
            }
        }
        else if (r->chunk.size == 0)
        {
            r->chunk.end = 1;
            if (r->resp.len == 2)
            {
                return 1;
            }
            else if (r->resp.len < 2)
            {
                r->chunk.size = 2 - r->resp.len;
                r->resp.len = 0;
                break;
            }
            else
            {
                fprintf(stderr, "<%s:%d:%d:%d> ??? r->resp.len=%ld\n", 
                        __func__, __LINE__, r->num_conn, r->num_req, r->resp.len);
                return -1;
            }
        }
        else
        {
            if (r->chunk.size == ERR_TRY_AGAIN)
            {
                memmove(r->resp.buf, r->resp.ptr, r->resp.len);
                r->resp.ptr = r->resp.buf;
                r->chunk.size = -1;
                break;
            }
            else
                return -1;
        }
    }
    return 0;
}
