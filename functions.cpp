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
