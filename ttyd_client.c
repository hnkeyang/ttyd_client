 
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <openssl/ssl.h>

#include "websocket_common.h"
#include "console.h"

int run = 1;
struct tty_conn *conn;


void signal_handle(int sig){
    if(sig == SIGINT){
        printf("\nget signal: Ctrl+c\n");
    }else if(sig == SIGPIPE){
        printf("\nget signal: socket close\n");
    }else {
        printf("get signal\n");
    }
    run = 0;
    tty_reset();
    exit(0);
}

static void sig_winch(int sig) {
	unsigned short width, height;
	int plen;

	/* terminal height/width has changed, inform server */
	if (get_terminal_size(&width, &height) != -1) {
        char tty_cw[64] = {0};
        sprintf(tty_cw, "1{\"columns\":%u,\"rows\":%u}", width, height);
        int ret = webSocket_send(conn, tty_cw, strlen(tty_cw), true, WCT_BINDATA);
        if (ret < 0){
            printf("window change failed\n");
        }
	}

	/* reinstate signal handler */
	signal(SIGWINCH, sig_winch);
}

int read_from_socket()
{
    int len = 65535;
    char buf[len];

    int nread = webSocket_recv(conn, buf, len);
    int ws_type = 0;
    unsigned int ws_len = 0;
    unsigned char *webSocketPackage;
    int total_read_len = 0;
    while(total_read_len < nread){
        int packageMaxLen = nread + 128;
        webSocketPackage = (unsigned char *)calloc(1, sizeof(char)*packageMaxLen);
        memset(webSocketPackage, 0, packageMaxLen);
        ws_type = webSocket_dePackage(buf + total_read_len, nread - total_read_len, webSocketPackage, packageMaxLen, &ws_len);

        if(ws_type == WCT_PING)      // 解析为ping包, 自动回pong
        {
            webSocket_send(conn, webSocketPackage, ws_len, true, WCT_PONG);
            // 显示数据
            // printf("webSocket_recv : PING len:%d data: %s\r\n, send PONG" , ws_len, webSocketPackage); 

        }
        else if(ws_type == WCT_PONG){
            // printf("webSocket_recv : PONG len:%d data: %s\r\n" , ws_len, webSocketPackage); 
        }

        //接收的消息第一字节是0，后面是消息内容
        else
        {
            if(webSocketPackage[0] == '0'){
                // write(STDOUT_FILENO, webSocketPackage+1, ws_len-1);
                fwrite(webSocketPackage+1, 1, ws_len-1, stdout);
                fflush(stdout);
            }
        }
        
        free(webSocketPackage);
        total_read_len +=  ws_len + 2;
    }
    if(nread <= 0){
        tty_reset();
        // printf("exit nread <= 0, nread: %d\n", nread);
        exit(1);
    }

    return 0;
}

int read_from_stdin(){
    int ret;

    char c;
    //每次按键通过websocket发出去的消息，第一字节是0，第二字节是按下的键
    char cmd[3];
    cmd[0] = '0';
    cmd[2] = '\0';

    c = getchar();

    // ctrl + ] exit ttyd_client
    if(c == 29){
        run = 0;
    }

    cmd[1] = c;
    ret = webSocket_send(conn, cmd, strlen(cmd), true, WCT_BINDATA);
    return ret;
}

int main(int argc, char *argv[])
{
    signal(SIGINT, signal_handle);
    signal(SIGPIPE, signal_handle);

    char hostname[100] = {0};
    int port;
    char uri[100] = {0};
    if ( argc < 2 )
    {
        printf("usage: %s https://192.168.1.1/ttyd\n", argv[0]);
        exit(0);
    }

    conn = malloc(sizeof(conn));
    conn->use_ssl = 0;
    
    char *hostname_tmp = argv[1];

    // https://192.168.1.1/tty
    // 删除开头的 https://
    if(strncmp(hostname_tmp, "https://", 8) == 0){
        hostname_tmp = hostname_tmp + 8;
        conn->use_ssl = 1;
    }else if(strncmp(hostname_tmp, "http://", 7) == 0){
        hostname_tmp = hostname_tmp + 7;
        conn->use_ssl = 0;
    }

    // 删除后面的 uri 
    char *uri_tmp = strchr(hostname_tmp, '/');
    if(uri_tmp != NULL){
        memcpy(uri, uri_tmp, strlen(uri_tmp));
        hostname_tmp[uri_tmp-hostname_tmp] = '\0';
    }
    strcat(uri, "/ws");

    // 从 URL 里取冒号后面的端口
    char *port_url = strchr(hostname_tmp, ':');
    if(port_url != NULL){
        strncpy(hostname, hostname_tmp, port_url - hostname_tmp);
        port = atoi(port_url+1);
    }else{
        strcpy(hostname, hostname_tmp);
        if(conn->use_ssl){
            port = 443;
        } else {
            port = 80;
        }
    }

    printf("enable_ssl?: %d, hostname: %s, port: %d, uri: %s\n\n", conn->use_ssl, hostname, port, uri);

    int ret;

    ret = webSocket_clientLinkToServer(conn, hostname, port, uri);
    if(ret < 0){
        printf("webSocket_clientLinkToServer error\n");
        exit(1);
    }

    signal(SIGWINCH, sig_winch);
     
    char *auth = "{\"AuthToken\":\"\"}";
    ret = webSocket_send(conn, auth, strlen(auth), true, WCT_BINDATA);

    char tty_cw[64] = {0};
    unsigned short width, height;
	if (get_terminal_size(&width, &height) != -1) {
        sprintf(tty_cw, "1{\"columns\":%u,\"rows\":%u}", width, height);
        ret = webSocket_send(conn, tty_cw, strlen(tty_cw), true, WCT_BINDATA);
        if (ret < 0){
            printf("main window change failed\n");
        }
	}

    fd_set fdsr;
    int maxsock;
    struct timeval tv;

    maxsock = conn->fd;

    tty_init();
    while(run == 1){
        FD_ZERO(&fdsr);
        FD_SET(0, &fdsr);
        FD_SET(conn->fd, &fdsr);

        tv.tv_sec = 0;
        tv.tv_usec = 10000;

        ret = select(maxsock + 1, &fdsr, NULL, NULL, &tv);
        if (ret < 0) {
            perror("select error");
            break;
        } else if (ret == 0) {
            // printf("timeout\n");
            continue;
        }

        if (FD_ISSET(conn->fd, &fdsr)) {
            read_from_socket();
        }

        if (FD_ISSET(0, &fdsr)) {

            ret = read_from_stdin();
            if(ret < 0){
                printf("read_from_stdin error: %d\n", ret);
                break;
            }

        }
    }
    
    tty_reset();
    printf("client close !\r\n");

    return 0;
}
