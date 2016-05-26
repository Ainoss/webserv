#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include "picohttpparser.h"

#define HTTP_IN 1
#define HTTP_OUT_HEADER 2
#define HTTP_OUT_CONTENT 3
#define HTTP_SHUT 4

#define MAX_EVENTS 32
#define MAX_HEADERS 32
#define BUFFER_SIZE 4096

#define WEB_ROOT "./html_example/"

typedef struct conn_info {
    int sockfd;
    int state;
    char *buf;
    int size_buf;
    int written;
    char *content;
    int size_content;
    char *content_mime;
    int f_map;
} conn_info_t;

typedef struct list_node {
    struct list_node *next;
    conn_info_t data;
} list_node_t;

struct http_request {
    const char *method;
    size_t method_len;
    const char *path;
    size_t path_len;
    struct phr_header headers[MAX_HEADERS];
    size_t headers_len;
};

int create_listen()
{
    int listenfd;
    int i, flags;
    struct sockaddr_in sa_in;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd == -1){
        perror("Socket creation");
        return 1;
    }

    i = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) == -1){
        perror("setsockopt listen");
        goto list_err;
    }

    sa_in.sin_family = AF_INET;
    sa_in.sin_addr.s_addr = htonl(INADDR_ANY);
    sa_in.sin_port = htons(8080);

    if (bind(listenfd, (struct sockaddr*)  &sa_in, sizeof(sa_in)) == -1){
        perror("Bind");
        goto list_err;
    }

    flags = fcntl(listenfd, F_GETFL, 0);
    if (flags == -1){
        perror("fcntl listenfd");
        goto list_err;
    }
    if (fcntl(listenfd, F_SETFL, flags | O_NONBLOCK) == -1){
        perror("fcntl listenfd");
        goto list_err;
    }

    listen(listenfd, 16);
    
    return listenfd;
list_err:
    close(listenfd);
    return -1;
}

int list_add(list_node_t **list_head, list_node_t *node)
{
    node->next = *list_head;
    *list_head = node;
    return 0;
}

int list_del(list_node_t **list_head, list_node_t *node)
{
    list_node_t *tmp, *prev = NULL;
    for (tmp = *list_head; tmp; tmp = tmp->next){
        if (tmp == node){
            if (prev)
                prev->next = node->next;
            else 
                *list_head = node->next;
        }
        prev = tmp;
    }
    return 0;
}

int create_con(int listenfd, conn_info_t *data)
{
    int connfd;
    int flags;
    connfd = accept(listenfd, NULL, NULL); 
    if (connfd == -1){
        perror("Accept");
        return -1;
    }

    flags = fcntl(connfd, F_GETFL, 0);
    if (flags == -1){
        perror("fcntl listenfd");
        return -1;
    }
    if (fcntl(connfd, F_SETFL, flags | O_NONBLOCK) == -1){
        perror("fcntl listenfd");
        return -1;
    }

    data->sockfd = connfd;
    data->state = HTTP_IN;
    data->buf = malloc(BUFFER_SIZE);
    if (data->buf == NULL){
        perror("connection buffer");
        return -1;
    }
    data->size_buf = BUFFER_SIZE;

    return 0;
}

int recv_con(conn_info_t *info)
{
    int bytes;
    errno = 0;
    bytes = recv(info->sockfd, info->buf + info->written, 
                 info->size_buf - info->written, 0);
    if (bytes == 0){
        printf("Connection unexpectedly closed\n");
        return 0;
    }
    else if (bytes == -1){
        if (errno == EAGAIN || errno == EWOULDBLOCK){
            printf("EAGAIN!\n");
        }
        else{
            perror("recv");
            return -1;
        }
    }
    info->written += bytes;

    if (info->written == info->size_buf){
        printf("connection buffer overflow!");
    }
    printf("%.*s\n", (info->written > 32) ? 32 : info->written, info->buf);
    return bytes;
}

int send_con(conn_info_t *info)
{
    char *ptr;
    int size, bytes;

    if (info->state == HTTP_OUT_HEADER){
        ptr = info->buf + info->written;
        size = info->size_buf - info->written;
    }
    else {
        ptr = info->content + info->written;
        size = info->size_content - info->written;
    }
    bytes = send(info->sockfd, ptr, size, 0);
    if (bytes == -1){
        perror("recv");
        return -1;
    }
    info->written += bytes;

    if (bytes == size && info->state == HTTP_OUT_HEADER 
            && info->size_content)
    {
        info->written = 0;
        info->state = HTTP_OUT_CONTENT;
    }
    else if (bytes == size){
        info->state = HTTP_SHUT;
    }

    return bytes;
}

int close_con(conn_info_t *info)
{
    shutdown(info->sockfd, SHUT_RDWR);
    close(info->sockfd);

    if (info->content){
        if (info->f_map)
            munmap(info->content, info->size_content);
        else 
            free(info->content);
    }
    free(info->buf);
    return 0;
}

char *get_extension(char *path)
{
    char *last_dot = NULL;
    while (*path){
        if (*path == '.')
            last_dot = path;
        path++;
    }
    return last_dot ? ++last_dot : NULL;
}

int resp_get_file(conn_info_t *info, char *path, size_t size)
{
    int fd;
    char *mapping;
    char *ext;
    fd = open(path, O_RDONLY);
    if (fd == -1){
        perror("open path");
        return 404;
    }
    mapping = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED){
        perror("mmap path");
        close(fd);
        return 404;
    }
    close(fd);
    info->written = 0;
    info->content = mapping;
    info->size_content = size;
    info->f_map = 1;
    ext = get_extension(path);
    if (!ext)
        info->content_mime = "application/octet-stream";
    else if (!strcmp(ext, "html"))
        info->content_mime = "text/html";
    else if (!strcmp(ext, "jpg") || !strcmp(ext, "jpeg"))
        info->content_mime = "image/jpeg";
    else if (!strcmp(ext, "png"))
        info->content_mime = "image/png";
    else if (!strcmp(ext, "css"))
        info->content_mime = "text/css";
    else if (!strcmp(ext, "txt"))
        info->content_mime = "text/plain";
    else if (!strcmp(ext, "js"))
        info->content_mime = "application/javascript";
    printf("Extension %s\n", ext ? ext : "NONE");

    return 200;
}

int resp_get_index(conn_info_t *info, char *path)
{
    DIR *pdir;
    struct dirent *pentry;
    int size;
    char dir_string[512];
    pdir = opendir(path);
    if (pdir == NULL){
        perror("opendir");
        return 500;
    }
    info->content = malloc(BUFFER_SIZE);
    size = BUFFER_SIZE;

    sprintf(info->content, 
            "<!DOCTYPE HTML>\r\n"
            "<html>\r\n"
            " <head>\r\n"
            "  <title>Index of %s</title>\r\n"
            " </head>\r\n"
            "<body>\r\n\r\n", 
            path);
    info->size_content = strlen(info->content);

    while (1){
        errno = 0;
        pentry = readdir(pdir);
        if (errno != 0){
            perror("readdir");
            return 500;
        }
        else if (pentry == NULL)
            break;

        if (pentry->d_name[0] == '.')
            continue;
        if (pentry->d_type == DT_DIR)
            sprintf(dir_string, "<a href=\"%s/\">%s/</a><br>\r\n", pentry->d_name, pentry->d_name);
        else 
            sprintf(dir_string, "<a href=\"%s\">%s</a><br>\r\n", pentry->d_name, pentry->d_name);
        info->size_content += strlen(dir_string);
        if (info->size_content > size){
            size *= 2;
            info->content = realloc(info->content, size);
        }
        strcat(info->content, dir_string);
    }
    strcat(info->content, "</body> </html>");
    info->content_mime = "text/html";

    closedir(pdir);
    return 200;
}

int generate_header(conn_info_t *info, int status)
{
    char *status_msg;
    printf("Response status %d\n", status);

    /* Generate header */
    switch (status){
        case 200:
            status_msg = "200 OK";
            break;
        case 400:
            status_msg = "400 Bad Request";
            break;
        case 404:
            status_msg = "404 Not Found";
            break;
        case 405:
            status_msg = "405 Method Not Allowed";
            break;
        case 501:
            status_msg = "501 Not Implemented";
            break;
        default:
            status_msg = "500 Internal Server Error";
    }
    if (info->size_content){
        sprintf(info->buf, 
                "HTTP/1.0 %s\r\n"
                "Content-Length: %u\r\n"
                "Content-Type: %s\r\n\r\n",
                status_msg, info->size_content, info->content_mime);
    }
    else
        sprintf(info->buf, "HTTP/1.0 %s\r\n\r\n", status_msg);
    info->size_buf = strlen(info->buf);
    info->written = 0;
    info->state = HTTP_OUT_HEADER;

    return 0;
}

int generate_content(conn_info_t *info, const char *rel_path, size_t path_len)
{
    /* TODO Check URL */
    struct stat st;
    int status;
    char *path = malloc(strlen(WEB_ROOT) + path_len + 1);
    sprintf(path, "%s%.*s", WEB_ROOT, (int)path_len, rel_path);

    /* Check and generate content */
    if (stat(path, &st) == -1){
        perror("fstat");
        status = 404;
    }
    else if (S_ISREG(st.st_mode)){
        status = resp_get_file(info, path, st.st_size);
    }
    else if (S_ISDIR(st.st_mode)){
        status = resp_get_index(info, path);
    }
    else{
        printf("Bad file type\n");
        status = 501;
    }

    free(path);
    return status;
}

int parse_request(char *buf, size_t size, struct http_request *req)
{
    int parsed, minor_version;
    req->headers_len = MAX_HEADERS;
    parsed = phr_parse_request(buf, size, 
             &req->method, &req->method_len, 
             &req->path, &req->path_len, 
             &minor_version, 
             req->headers, &req->headers_len, 
             size);

    return parsed;
}

int process_request(conn_info_t *info)
{
    struct http_request req;
    int parsed, st;
    parsed = parse_request(info->buf, info->written, &req);
    if (parsed == -1){
        printf("Parsing error!\n");
        generate_header(info, 400);
        return 1;
    }
    else if (parsed > 0){
        if (strncmp(req.method, "GET", req.method_len)){
            printf("Incorrect method %.*s\n", (int)req.method_len, req.method);
            generate_header(info, 405);
        }
        else {
            printf("Request path: %.*s\n", (int)req.path_len, req.path);
            st = generate_content(info, req.path, req.path_len);
            generate_header(info, st);
        }
        return 1;
    }

    return 0;
}

int main()
{
    int ret = 1;
    int listenfd;
    int connfd;
    int epfd;
    struct epoll_event events[MAX_EVENTS];
    struct epoll_event ev;
    int n, i, bytes;
    list_node_t *lhead = NULL;
    list_node_t *node;
    conn_info_t *info;

    listenfd = create_listen();
    if (listenfd == -1){
        perror("listen socket creation");
        return 1;
    }

    epfd = epoll_create(1);
    if (epfd == -1){
        perror("epoll creating");
        close(listenfd);
        return 1;
    }

    ev.events = EPOLLIN;
    ev.data.ptr = NULL;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev) == -1){
        perror("epoll ctl");
        goto conn_err;
    }

    while (1){
        n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (n == -1){
            perror("epoll wait");
            goto conn_err;
        }

        for (i = 0; i < n; i++){
            if (events[i].data.ptr == NULL){
                node = malloc(sizeof(*node));
                memset(node, 0, sizeof(*node));
                if (create_con(listenfd, &node->data) == -1){
                    free(node);
                    goto conn_err;
                }
                list_add(&lhead, node);
                printf("ep: accept %d fd, info %p\n", node->data.sockfd, (void*)&node->data);

                ev.events = EPOLLIN;
                ev.data.ptr = &node->data;
                if (epoll_ctl(epfd, EPOLL_CTL_ADD, node->data.sockfd, &ev) == -1){
                    perror("epoll ctl");
                    goto conn_err;
                }
                continue;
            }
            else if (events[i].events & EPOLLIN){
                info = events[i].data.ptr;
                printf("ep: recv from %d fd, info %p\n", info->sockfd, info);
                bytes = recv_con(info);
                if (bytes == -1)
                    goto conn_err;
                else if (bytes == 0){
                    if (epoll_ctl(epfd, EPOLL_CTL_DEL, info->sockfd, NULL) == -1){
                        perror("epoll ctl");
                        goto conn_err;
                    }

                    close_con(info);
                    node = (void*)((intptr_t)info + (intptr_t)lhead - (intptr_t)&lhead->data);
                    list_del(&lhead, node);
                    free(node);
                }

                
                if (process_request(info)){
                    ev.events = EPOLLOUT;
                    ev.data.ptr = info;
                    if (epoll_ctl(epfd, EPOLL_CTL_MOD, info->sockfd, &ev) == -1){
                        perror("epoll ctl");
                        goto conn_err;
                    }
                }
            }
            else if (events[i].events & EPOLLOUT){
                info = events[i].data.ptr;

                bytes = send_con(info);
                if (bytes == -1)
                    goto conn_err;

                printf("ep: sent %db to %d fd, info %p\n", bytes, info->sockfd, info);
                if (info->state == HTTP_SHUT){
                    if (epoll_ctl(epfd, EPOLL_CTL_DEL, info->sockfd, NULL) == -1){
                        perror("epoll ctl");
                        goto conn_err;
                    }

                    printf("ep: buffer sent, close desc\n");
                    close_con(info);
                    node = (void*)((intptr_t)info + (intptr_t)lhead - (intptr_t)&lhead->data);
                    list_del(&lhead, node);
                    free(node);
                }
                continue;
            }
            else if (events[i].events & EPOLLERR){
                info = events[i].data.ptr;
                printf("error event on socket %d!\n", info->sockfd);
            }

        }

    }

    ret = 0;
conn_err:
    for (node = lhead; node; node = node->next){
        close_con(&node->data);
        free(node);
    }
    close(listenfd);
    close(epfd);
    return ret;
}

