#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <netinet/in.h>

#define HTTP_IN 1
#define HTTP_OUT 2

#define MAX_EVENTS 32
#define BUFFER_SIZE 4096

typedef struct conn_info {
    int sockfd;
    int state;
    char *buf;
    int size_buf;
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
                printf("ep: accept\n");
                connfd = accept(listenfd, NULL, NULL); 
                if (connfd == -1){
                    perror("Accept");
                    goto conn_err;
                }
                if (fcntl(connfd, F_SETFD, O_NONBLOCK) == -1){
                    perror("fcntl listenfd");
                    goto conn_err;
                }

                node = lhead;
                lhead = malloc(sizeof(*lhead));
                lhead->next = node;
                lhead->data.sockfd = connfd;
                lhead->data.state = HTTP_IN;
                lhead->data.buf = malloc(BUFFER_SIZE);
                if (lhead->data.buf == NULL){
                    perror("connection buffer");
                    goto conn_err;
                }
                lhead->data.size_buf = BUFFER_SIZE;

                ev.events = EPOLLIN;
                ev.data.ptr = &lhead->data;
                if (epoll_ctl(epfd, EPOLL_CTL_ADD, connfd, &ev) == -1){
                    perror("epoll ctl");
                    goto conn_err;
                }

                continue;
            }
            if (events[i].events & EPOLLIN){
                printf("ep: recv\n");
                info = events[i].data.ptr;
                bytes = recv(info->sockfd, info->buf, info->size_buf, 0);
                if (bytes == 0){
                    printf("Connection unexpectedly closed\n");
                    continue;
                }
                else if (bytes == -1){
                    perror("recv");
                    goto conn_err;
                }
                printf("%.*s\n", bytes, info->buf);
                
                /* Let think that GET requests are small */
                info->state = HTTP_OUT;
                char resp_msg[] = "Ababa hahah!\n";
                //char resp_msg[] = "HTTP/1.0 200 OK\n\n";
                strcpy(info->buf, resp_msg);
                info->size_buf = strlen(resp_msg);

                ev.events = EPOLLOUT;
                ev.data.ptr = &lhead->data;
                if (epoll_ctl(epfd, EPOLL_CTL_MOD, info->sockfd, &ev) == -1){
                    perror("epoll ctl");
                    goto conn_err;
                }

            }
            if (events[i].events & EPOLLOUT){
                printf("ep: send\n");
                info = events[i].data.ptr;
                bytes = send(info->sockfd, info->buf, info->size_buf, 0);
                if (bytes == -1){
                    perror("recv");
                    goto conn_err;
                }
                else if (bytes != info->size_buf){
                    printf("Not whole buffer written\n");
                    continue;
                }

                if (epoll_ctl(epfd, EPOLL_CTL_DEL, info->sockfd, NULL) == -1){
                    perror("epoll ctl");
                    goto conn_err;
                }
                printf("ep: data sent %db\n", bytes);

                shutdown(info->sockfd, SHUT_RDWR);
                close(info->sockfd);
                continue;
            }
            if (events[i].events & EPOLLERR){
                printf("error!!!\n");
            }

        }

    }

    ret = 0;
conn_err:
    for (node = lhead; node; node = node->next){
        close(node->data.sockfd);
        free(node->data.buf);
        free(node);
    }
    close(listenfd);
    close(epfd);
    return ret;
}

