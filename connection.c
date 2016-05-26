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

#define MAX_EVENTS 32
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
    int f_map;
} conn_info_t;

typedef struct list_node {
    struct list_node *next;
    conn_info_t data;
} list_node_t;

int create_listen()
{
    int listenfd;
    int i;
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

    if (fcntl(listenfd, F_SETFD, O_NONBLOCK) == -1){
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

int accept_con(int listenfd, conn_info_t *data)
{
    int connfd;
    connfd = accept(listenfd, NULL, NULL); 
    if (connfd == -1){
        perror("Accept");
        return -1;
    }
    if (fcntl(connfd, F_SETFD, O_NONBLOCK) == -1){
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
    printf("%.*s\n", (bytes > 32) ? 32 : bytes, info->buf);
    return bytes;
}

int generate_response(conn_info_t *info, const char *rel_path, size_t path_len)
{
    /* TODO Check URL */
    struct stat st;
    int fd;
    int status;
    void *mapping;
    char err_msg[] = "HTTP/1.0 404 Not Found\r\n";
    char *status_msg;
    char *path = malloc(strlen(WEB_ROOT) + path_len + 2);
    sprintf(path, "%s/%.*s", WEB_ROOT, (int)path_len, rel_path);

    if (stat(path, &st) == -1){
        perror("fstat");
        goto respond_err;
    }
    if (S_ISREG(st.st_mode)){
        fd = open(path, O_RDONLY);
        if (fd == -1){
            perror("open path");
            status = 404;
            goto respond_err;
        }
        mapping = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
        if (mapping == MAP_FAILED){
            perror("mmap path");
            close(fd);
            status = 404;
            goto respond_err;
        }
        close(fd);
        info->written = 0;
        info->content = mapping;
        info->size_content = st.st_size;
        info->f_map = 1;
        status = 200;
    }
    else if (S_ISDIR(st.st_mode)){
        DIR *pdir;
        struct dirent *pentry;
        int size;
        char dir_string[512];
        pdir = opendir(path);
        if (pdir == NULL){
            perror("opendir");
            status = 500;
            goto respond_err;
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
                status = 500;
                goto respond_err;
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

        closedir(pdir);
        status = 200;
    }
    else{
        printf("Path is not a file\n");
        status = 501;
        goto respond_err;
    }

respond_err:
    switch (status){
        case 200:
            status_msg = "200 OK";
            break;
        case 404:
            status_msg = "404 Not Found";
            break;
        case 501:
            status_msg = "501 Not Implemented";
            break;
        default:
            status_msg = "500 Internal Server Error";
    }
    sprintf(info->buf, 
            "HTTP/1.0 %s\r\n"
            "Content-Length: %u\r\n\r\n",
        //    "Content-Type: text/html\r\n\r\n",
            status_msg, info->size_content);
    info->size_buf = strlen(info->buf);
    info->written = 0;
    info->state = HTTP_OUT_HEADER;
    free(path);
    return 0;
}

int parse_request(char *buf, size_t size, const char **path, size_t *path_len)
{
    const char *method;
    size_t method_len, headers_len = 32;
    int parsed, minor_version;
    struct phr_header headers[32];
    parsed = phr_parse_request(buf, size, &method, &method_len, path, path_len, &minor_version, headers, &headers_len, size);

    return parsed;
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
        printf("epoll get %u events\n", n);

        for (i = 0; i < n; i++){
            if (events[i].data.ptr == NULL){
                node = malloc(sizeof(*node));
                memset(node, 0, sizeof(*node));
                if (accept_con(listenfd, &node->data) == -1){
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
                if (recv_con(info) == -1){
                    goto conn_err;
                }
                
                const char *path;
                size_t path_len;
                int parsed;
                parsed = parse_request(info->buf, info->written, &path, &path_len);
                printf("Parsed with %d status\n", parsed);
                if (parsed == -1){
                    printf("Parsing error!\n");
                }
                else if (parsed > 0){
                    printf("Request path: %.*s\n", (int)path_len, path);
                    generate_response(info, path, path_len);

                    ev.events = EPOLLOUT;
                    ev.data.ptr = info;
                    if (epoll_ctl(epfd, EPOLL_CTL_MOD, info->sockfd, &ev) == -1){
                        perror("epoll ctl");
                        goto conn_err;
                    }
                }
            }
            else if (events[i].events & EPOLLOUT){
                char *ptr;
                int size;
                info = events[i].data.ptr;

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
                    goto conn_err;
                }
                info->written += bytes;

                printf("ep: sent %db to %d fdm info %p\n", bytes, info->sockfd, info);
                if (info->written == size && info->state == HTTP_OUT_HEADER 
                        && info->size_content)
                {
                    info->written = 0;
                    info->state = HTTP_OUT_CONTENT;
                }
                else if (info->written == size){
                    if (epoll_ctl(epfd, EPOLL_CTL_DEL, info->sockfd, NULL) == -1){
                        perror("epoll ctl");
                        goto conn_err;
                    }

                    printf("ep: buffer sent, close desc\n");
                    shutdown(info->sockfd, SHUT_RDWR);
                    close(info->sockfd);

                    if (info->content){
                        if (info->f_map)
                            munmap(info->content, info->size_content);
                        else 
                            free(info->content);
                    }
                    free(info->buf);
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
        shutdown(node->data.sockfd, SHUT_RDWR);
        close(node->data.sockfd);
        if (node->data.content){
            if (node->data.f_map)
                munmap(node->data.content, node->data.size_content);
            else 
                free(node->data.content);
        }
        free(node->data.buf);
        free(node);
    }
    close(listenfd);
    close(epfd);
    return ret;
}

