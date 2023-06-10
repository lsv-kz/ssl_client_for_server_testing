#ifndef CLIENT_H
#define CLIENT_H

#define _FILE_OFFSET_BITS 64
#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <errno.h>

#include <mutex>
#include <thread>
#include <condition_variable>

#include <limits.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

extern char Host[128];
extern char IP[256];
extern int ai_family;
extern char Uri[1024];
extern int MaxThreads;
extern char Method[16];
extern int connKeepAlive;

extern const char *end_line;

const int  ERR_TRY_AGAIN = -1000;

const int  SIZE_BUF = 32768;

enum PROTOCOL {HTTP = 1, HTTPS};
enum OPERATION_TYPE { SSL_CONNECT = 1, SEND_REQUEST, READ_RESP_HEADERS, READ_ENTITY, };
enum IO_STATUS { POLL = 1, WORK };

struct Config {
    SSL_CTX *ctx;
    PROTOCOL Protocol;

    int  num_connections;
    int  num_requests;

    char  Trigger;

    int  connKeepAlive;
    int  Timeout;
    int  TimeoutPoll;
    char ip[256];
    char port[32];
    const char *req;
    int (*create_sock)(const char*, const char*, int*);
};
extern const Config* const conf;
//----------------------------------------------------------------------
struct Connect {
    Connect *prev;
    Connect *next;

    SSL   *ssl;
    int   ssl_err;

    OPERATION_TYPE operation;
    IO_STATUS    io_status;

    int    num_proc;
    int    num_conn;
    int    num_req;

    int    err;

    int    servSocket;

    time_t sock_timer;
    int    timeout;
    int    event;

    struct
    {
        const char *ptr;
        int len;
        int i;
    } req;

    struct
    {
        char  buf[SIZE_BUF];
        long  len;
        long  lenTail;
        char  *ptr;
        char  *p_newline;
    } resp;

    struct
    {
        int  chunk;
        long  size;
        int  end;
    } chunk;

    char   server[128];
    long long  cont_len;
    int    connKeepAlive;
    int    respStatus;
    long long  read_bytes;
};
//----------------------------------------------------------------------
int child_proc(int, const char*);
//----------------------------------------------------------------------
int send_headers(Connect *r);
int get_good_req(void);
int get_good_conn(void);
long long get_all_read(void);
void thr_client(int num_proc);
void push_to_wait_list(Connect *r);

int trig_get_good_req(void);
int trig_get_good_conn(void);
long long trig_get_all_read(void);
void thr_client_trigger(int num_proc);
void trig_push_to_wait_list(Connect *r);
//----------------------------------------------------------------------
int read_req_file(const char *path, char *req, int size);
int write_to_server(Connect *req, const char *buf, int len);
int read_from_server(Connect *req, char *buf, int len);
int read_http_headers(Connect *r);
//----------------------------------------------------------------------
int create_client_socket(const char * host, const char *port);
int create_client_socket_ip4(const char *ip, const char *port, int*);
int create_client_socket_ip6(const char *ip, const char *port, int*);
int get_ip(int sock, char *ip, int size_ip);
const char *get_str_ai_family(int ai_family);
//----------------------------------------------------------------------
void std_in(char *s, int len);
const char *strstr_case(const char *s1, const char *s2);
int strcmp_case(const char *s1, const char *s2);
int strlcmp_case(const char *s1, const char *s2, int len);
int parse_headers(Connect *r, char *s);
int create_log_file();
const char *get_str_operation(OPERATION_TYPE n);
void hex_dump_stderr(const void *p, int n);
void hex_dump_stderr(const char *s, int line, const void *p, int n);
//----------------------------------------------------------------------
SSL_CTX* InitCTX();
const char *ssl_strerror(int err);
int ssl_read(Connect *req, char *buf, int len);
int ssl_write(Connect *req, const char *buf, int len);

#endif
