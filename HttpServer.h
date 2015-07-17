#ifndef HTTPSERVER_H
#define HTTPSERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <dirent.h>



#include "openssl/ssl.h"
#include "openssl/err.h"
#define FAIL -1



#ifdef linux
#include <ctype.h>
#endif

#include "ReadConfFile.h"
#include "MD5.h"

#define SERVER_VERSION "HttpServer/2.1"

#ifdef linux
#define BUFFER_SIZE 1460
#else
#define BUFFER_SIZE 1448
#endif


char DOCUMENT_ROOT[512] ;
int SERVER_MODE ; // 0: only http ; 1: only https ; >1: http and https ;
int HTTP_PORT ;
int HTTPS_PORT ;
int DEBUG_MODE ;
int CONNECT_TIME_OUT , SENDDATA_TIME_OUT ;
char LOG_FILE_PATH[256] ;
int MAXNUM_PROCESS;
char CERT_FILE_PATH[256] ;
char KEY_FILE_PATH[256] ;



char logstring[1024];
int client_fd ;
int process_num;
int isHttpsProcess ;
SSL *ssl_client;
SSL_CTX *ctx;

char REQUEST_METHOD[10] ;
char REQUEST_URI[1024] ;
char SCRIPT_NAME[1024];
char QUERY_STRING[1024] ;
char HTTP_HOST[100] , HTTP_CACHE_CONTROL[100], HTTP_ACCEPT_ENCODING[100], HTTP_USER_AGENT[1000] , HTTP_ORIGIN[256] , HTTP_CONNECTION[100] , HTTP_ACCEPT_LANGUAGE[100] , HTTP_REFERER[1000] , HTTP_ACCEPT[200] , CONTENT_LENGTH[100] , CONTENT_TYPE[200] , HTTP_COOKIE[1000] , HTTP_RANGE[100] , HTTP_IFRANGE[100] ;
	

void WriteLogString(char * str) ;
void SendNotFound() ;
void SendUnimplementedMethod() ;
void SendBadRequest() ; 
void SendMovedPermanently( char * newUrl) ;
long SendHtmlContent(char * path ) ;

void GetMethodUrl( char * buffer , char * method , char * requestUrl ) ;
void GetContentTypeByExName( char * path , char * ContentType) ;
void GetPara(char * buffer , char * dest , int start  );
void DelRepeatedChar( char * buffer , char c );
int Hex2Int(char * hex );
void DealPath(char * path );
int isFileExist(char * filePath);

void ChildProcessExit(int sig);
void ChildProcessTimeOut(int sig);

void execCgiBin( char * FullPath , char * REQUEST_METHOD , char *  QUERY_STRING );
void DealWithClient() ;
int StartSocketServer(int port) ;


#endif
