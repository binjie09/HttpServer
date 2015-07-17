#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define FAIL -1


int OpenConnection(const char *hostname, int port)
{
	int sd;
	struct hostent *host;
	struct sockaddr_in addr;

	if ( (host = gethostbyname(hostname)) == NULL )
	{
		printf("Eroor: %s\n",hostname);
		perror(hostname);
		abort();
	}

	sd = socket(PF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);

	if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		close(sd);
		perror(hostname);
		abort();
	}

	return sd;
}

int main(int argc, char *argv[])
{
	int server;
	char buf[10240];
	int bytes;
	char *hostname, *portnum;

	if ( argc != 4 )
	{
		printf("usage: %s <hostname> <portnum> <path>\n", argv[0]);
		exit(0);
	}
	hostname = argv[1];
	portnum = argv[2];

	server = OpenConnection( hostname , atoi(portnum) ) ;

	//char *msg = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36\r\nAccept-Encoding: deflate,sdch\r\nAccept-Language: zh-CN,zh;q=0.8,en;q=0.6,ja;q=0.4\r\n\r\n";
	char * fmt = "GET %s HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36\r\nAccept-Encoding: deflate,sdch\r\nAccept-Language: zh-CN,zh;q=0.8,en;q=0.6,ja;q=0.4\r\n\r\n";
	
	char msg[10240] ;
	sprintf(msg , fmt , argv[3] ) ;

	if( send( server , msg , strlen(msg) , 0 ) < 0 )
	{
		perror("Error(send)");	
		exit(1);
	}
	else
	{
		printf("Send message successfully !!!\n") ;
	}
	printf("Receive: ================================================================\n");
	bzero( buf , sizeof(buf) ) ;
	bytes = read( server , buf , sizeof(buf) ) ;
	while( bytes > 0 ) 
	{
		buf[bytes] = '\0' ;
		printf("%s", buf);
		bzero( buf , sizeof(buf) ) ;
		bytes = read( server , buf , sizeof(buf) ) ; 
	}
	printf("=========================================================================\n");

	close(server); /* close socket */

	return 0;
}
