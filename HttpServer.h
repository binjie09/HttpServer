#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <sys/wait.h>

#include "ReadConfFile.h"

#define SERVER_STRING "Server: HttpServer/1.1.0\r\n"

char DOCUMENT_ROOT[512] ;
int SERVER_PORT ;
char LOG_FILE_PATH[256] ;


void writelogstring(char * str) ;
void SendNotFound(int client) ;
void SendUnimplementedMethod(int client) ;
void SendBadRequest(int client) ; 
void SendMovedPermanently(int client , char * newUrl) ;
void SendOkHeaders(int client) ;
void SendHtmlContent(int client, char * path ) ;

void GetMethodUrl( char * buffer , char * method , char * requestUrl ) ;
void GetContentTypeByExName( char * path , char * ContentType) ;
void GetPara(char * buffer , char * dest , int start  );
void DelRepeatedChar( char * buffer , char c );
int Hex2Int(char * hex );
void DealPath(char * path );
int isFileExist(char * filePath);


void execCgiBin(int client , char * FullPath , char * REQUEST_METHOD , char *  QUERY_STRING );
void DealWithClient(int clientfd) ;
void server() ;

