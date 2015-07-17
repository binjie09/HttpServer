#include "HttpServer.h"


SSL_CTX* InitServerCTX()
{
	SSL_CTX *ctx = NULL;

	#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	const SSL_METHOD *method;
	#else
	SSL_METHOD *method;
	#endif

	SSL_library_init();
	OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
	SSL_load_error_strings();   /* load all error messages */
	method = SSLv23_server_method(); /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */

	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	//New lines
	if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
		ERR_print_errors_fp(stderr);
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
		ERR_print_errors_fp(stderr);
	//End new lines
	/* set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}

	//printf("INFO: LoadCertificates Compleate Successfully.....\n");
}

void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */

	if ( cert != NULL )
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("No certificates.\n");
}


void ChildProcessExit(int sig)
{
	pid_t pid;
	int waiter;
	while( (pid = waitpid(-1, &waiter, WNOHANG)) > 0 )
	{
		process_num-- ;
		if( DEBUG_MODE > 0 ) printf("[-------------------] %s[%d] : Process Exit (%d) ; process_num:%d ; pid:%d !\n",isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid() ,sig,process_num,pid) ;
	}
	
}

void ChildProcessTimeOut(int sig)
{
	if( DEBUG_MODE > 0 ) printf("[-------------------] %s[%d] : Time Out (%d)!\n", isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid() , sig) ;
	strcat( logstring , "Time Out !" ) ;
	WriteLogString(logstring) ;
	if( client_fd > 0 )
	{
		if( isHttpsProcess == 1 ) free(ssl_client) ;
		close(client_fd) ;
	}
	exit(0);
}


void WriteLogString(char * str)
{
	FILE * log_file;
	time_t now;
	struct tm  *timenow;
	log_file=fopen(LOG_FILE_PATH,"a");
	time(&now);
	timenow = localtime(&now);
	fprintf(log_file,"[%d-%02d-%02d %02d:%02d:%02d] %s\n",(1900+timenow->tm_year),(1+timenow->tm_mon),timenow->tm_mday,timenow->tm_hour,timenow->tm_min,timenow->tm_sec,str);
	fclose(log_file);
}

int ReadOneLine( char *buf, int size)
{
	int i = 0;
	char c = '\0';
	char d = '\0' ;
	int n;

	while ((i < size - 1) && (c != '\n'))
	{
		if( d == '\0' )
		{
			if( isHttpsProcess == 1 ) 
			{
				n = SSL_read(ssl_client, &c, 1);
			}
			else
			{
				n = recv(client_fd, &c, 1, 0);
			}
		}
		else
		{
			c = d ;
			d = '\0' ;
		}
		/* DEBUG printf("%02X\n", c); */
		if (n > 0)
		{
			if (c == '\r')
			{
				if( isHttpsProcess == 1 ) 
				{
					n = SSL_read(ssl_client, &d, 1);
				}
				else
				{
					n = recv(client_fd, &d, 1, 0);
				}
				
				if ((n > 0) && (d == '\n'))
					c = d ;
				else
					c = '\n';
			}
			buf[i] = c;
			i++;
		}
		else
			c = '\n';
	}
	buf[i] = '\0';
	return(i);
}

void SendToClient(char * buf , int len )
{
	if( isHttpsProcess == 1 ) 
	{
		SSL_write(ssl_client, buf, len);
	}
	else
	{
		send(client_fd, buf, len, 0);
	}
}

//404
void SendNotFound()
{
	char buf[BUFFER_SIZE];

	sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
	SendToClient(buf, strlen(buf));
	sprintf( buf ,"Server: %s\r\n" , SERVER_VERSION );
	SendToClient(buf, strlen(buf));
	sprintf(buf, "Connection: close\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "Content-Type: text/html\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "<BODY><P>The server could not fulfill<P>\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "your request because the resource specified<P>\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "is unavailable or nonexistent.\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "</BODY></HTML>\r\n");
	SendToClient(buf, strlen(buf));
}

//500
void SendInternalError()
{
 char buf[BUFFER_SIZE];

 sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
 SendToClient(buf, strlen(buf));
 sprintf(buf, "Content-type: text/html\r\n");
 SendToClient(buf, strlen(buf));
 sprintf(buf, "\r\n");
 SendToClient(buf, strlen(buf));
 sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
 SendToClient(buf, strlen(buf));
}

//501
void SendUnimplementedMethod()
{
	char buf[BUFFER_SIZE];
	
	sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
	SendToClient(buf, strlen(buf));
	sprintf( buf ,"Server: %s\r\n" , SERVER_VERSION );
	SendToClient(buf, strlen(buf));
	sprintf(buf, "Connection: close\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "Content-Type: text/html\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "</TITLE></HEAD>\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "</BODY></HTML>\r\n");
	SendToClient(buf, strlen(buf));
}

//400
void SendBadRequest()
{
	char buf[BUFFER_SIZE];
	
	sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "Connection: close\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "Content-type: text/html\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "<P>Your browser sent a bad request, ");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "such as a POST without a Content-Length.\r\n");
	SendToClient(buf, strlen(buf));
}

//301
void SendMovedPermanently(char * newUrl)
{
	char buf[BUFFER_SIZE];
	
	strcpy(buf, "HTTP/1.0 301 Moved Permanently\r\n");
	SendToClient(buf, strlen(buf));
	sprintf( buf ,"Server: %s\r\n" , SERVER_VERSION );
	SendToClient(buf, strlen(buf));
	sprintf(buf, "Location: %s\r\n", newUrl);
	SendToClient(buf, strlen(buf));
	sprintf(buf, "Connection: close\r\n");
	SendToClient(buf, strlen(buf));
	sprintf(buf, "Content-Type: text/html\r\n");
	SendToClient(buf, strlen(buf));
	strcpy(buf, "\r\n");
	SendToClient(buf, strlen(buf));
}


//200 content
long SendHtmlContent(char * path )
{
	FILE *resource ;
	char buf[BUFFER_SIZE];
	char ContentType[50] ;
	int len ;
	int flag;
	long fileLength ;
	char fileMD5[MD5_STR_LEN+1];
	long fStart = 0;
	long fEnd = -1 ;
	long fSend = 0 ;
	
	GetContentTypeByExName(path , ContentType ) ;
	if( DEBUG_MODE > 1 ) printf( "\tContentType : %s\n" , ContentType ) ;
	resource = fopen( path , "rb") ;

	//Get File Size 
	fseek(resource, 0L, SEEK_END); // go to file end
	fileLength = ftell(resource); //Get offset from head
	flag = Compute_file_md5(path, fileMD5);
	if( flag != 0 ){
		fileMD5[0] = '\0' ;
	}
	sprintf(buf , "\"%s\"" , fileMD5 ) ;
	
	flag = 0 ;
	fEnd=fileLength -1 ;
	if( strlen( HTTP_IFRANGE) > 10 ) 
	{
		if( ! strncasecmp( HTTP_IFRANGE ,buf , strlen(HTTP_IFRANGE) )  ) 
		{
			flag = 1 ;
			if( DEBUG_MODE > 1 ) printf( "[-------------------] %s[%d] : HTTP_RANGE = %s\n", isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid(), HTTP_RANGE) ;
			sscanf(HTTP_RANGE,"bytes=%ld-%ld",&fStart,&fEnd) ;
		}
	}
	if( fStart > fileLength -1 ) fStart = fileLength - 1 ;
	if( fStart < 0 ) fStart = 0 ;
	if( fEnd > fileLength -1  ) fEnd = fileLength - 1 ;
	if( fEnd < 0 ) fEnd = fileLength - 1 ;
	fSend = fEnd-fStart+1 ;
	
	
	sprintf( buf ,"HTTP/1.0 200 OK\r\nServer: %s\r\nConnection: close\r\nContent-Type: %s\r\nETag: \"%s\"\r\nAccept-Ranges: bytes\r\nContent-Length: %ld\r\n" , SERVER_VERSION ,ContentType,fileMD5,fSend);
	if( DEBUG_MODE > 2 ) printf( "[-------------------] %s[%d] : SEND ======================\n%s============================================\n" ,isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid() , buf ) ;
	SendToClient(buf, strlen(buf));	
	
	if( flag == 1 ) 
	{
		sprintf( buf ,"Content-Range: bytes %ld-%ld/%ld\r\n",fStart,fEnd,fileLength) ;
		if( DEBUG_MODE > 2 ) printf( "[-------------------] %s[%d] : SEND ======================\n%s============================================\n" , isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid() , buf ) ;
		SendToClient(buf, strlen(buf));	
	}
	strcpy(buf, "\r\n");
	SendToClient(buf, strlen(buf));
	
	fseek(resource, fStart, SEEK_SET); // move from head
		
	while(  fSend > 0 )
	{
		
		if(  fSend > BUFFER_SIZE  ) len = BUFFER_SIZE ;
		else len = fSend ;
		
		len = fread( buf , sizeof(char) , len , resource) ;
		SendToClient(buf, len);
		
		fSend -= len ;
		
		if( DEBUG_MODE > 3 ) printf( "[-------------------] %s[%d] : Send = %ld ; fSend = %ld  ; len = %d\n" ,isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid() , fileLength -fSend , fSend  , len ) ;

	}
		
	fclose(resource) ;
	return fEnd-fStart+1-fSend;
}


void SendDirectoryInfo( char * path)
{
	char buf[BUFFER_SIZE] ;
	DIR *dir;
	struct dirent *file;
	struct stat fs;	
	
	sprintf( buf ,"HTTP/1.0 200 OK\r\nServer: %s\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n" , SERVER_VERSION ) ;
	if( DEBUG_MODE > 2 ) printf( "[-------------------] %s[%d] : SEND ======================\n%s============================================\n" ,isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid() , buf ) ;
	SendToClient(buf, strlen(buf));
	
	
	if(!(dir=opendir(path)))
	{
		printf("ERROR !\n");
	}
	else
	{
		
		sprintf(buf,"<html>\n <head>\n  <title>Index of %s</title>\n </head>\n <body>\n<h1>Index of %s</h1>\n<table>\n<tr><th>Name</th><th>Size</th><th>Last modified</th></tr>\n<tr><th colspan=\"3\"><hr></th></tr>\n", REQUEST_URI , REQUEST_URI );
		SendToClient(buf, strlen(buf));
		if( DEBUG_MODE > 2 ) printf( "[-------------------] %s[%d] : SEND ======================\n%s" ,isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid() , buf ) ;
		
		sprintf(buf,"<tr><td><a href=\"%s../\" >Parent Directory</a></td><td>-</td><td>-</td></tr>\n" ,REQUEST_URI );
		SendToClient(buf, strlen(buf));
		if( DEBUG_MODE > 2 ) printf( "%s" , buf ) ;
		
		while( (file=readdir(dir)) != NULL )
		{
			sprintf( buf , "%s/%s" , path , file->d_name) ;
			lstat(buf,&fs);
			if(!(S_IFDIR&fs.st_mode))
			{
				sprintf(buf,"<tr><td><a href=\"%s\" >%s</a></td><td>%d</td><td>%s</td></tr>\n" ,file->d_name,file->d_name, (int)fs.st_size , asctime(gmtime(&fs.st_mtime)) );
				SendToClient(buf, strlen(buf));
				if( DEBUG_MODE > 2 ) printf( "%s" , buf ) ;
			}
			else
			{
				if(strcmp(file->d_name,".")==0||strcmp(file->d_name,"..")==0)
					continue;
				
				sprintf(buf,"<tr><td><a href=\"%s\" >%s</a></td><td>-</td><td>%s</td></tr>\n" ,file->d_name,file->d_name, asctime(gmtime(&fs.st_mtime)));
				SendToClient(buf, strlen(buf));
				if( DEBUG_MODE > 2 ) printf( "%s" , buf ) ;
			}
		}
		
		sprintf(buf,"<tr><th colspan=\"3\"><hr></th></tr>\n</table><address>%s at %s</address>\n</body></html>" ,SERVER_VERSION, HTTP_HOST);
		SendToClient(buf, strlen(buf));
		if( DEBUG_MODE > 2 ) printf( "%s\n============================================\n" , buf ) ;
	}
}


void GetContentTypeByExName( char * path , char * ContentType)
{
	int i , k , len ;
	char ExtName[20] ;
	len = strlen(path) ; 
	i = len-1 ;
	while( i > 0 &&  path[i] != '.'  ) i-- ;
	if( i < 0 )
	{
		strcpy( ContentType , "text/html" ) ;
		return ;
	}
	for( k = 0 ; i < len ; i++ , k++ ) ExtName[k] = path[i] ;
	ExtName[k] = '\0' ;

	if ( ! strncasecmp( ExtName , ".001" , strlen(".001") ) ) strcpy( ContentType , "application/x-001" ) ;
	else if ( ! strncasecmp( ExtName , ".301" , strlen(".301") ) ) strcpy( ContentType , "application/x-301" ) ;
	else if ( ! strncasecmp( ExtName , ".323" , strlen(".323") ) ) strcpy( ContentType , "text/h323" ) ;
	else if ( ! strncasecmp( ExtName , ".906" , strlen(".906") ) ) strcpy( ContentType , "application/x-906" ) ;
	else if ( ! strncasecmp( ExtName , ".907" , strlen(".907") ) ) strcpy( ContentType , "drawing/907" ) ;
	else if ( ! strncasecmp( ExtName , ".a11" , strlen(".a11") ) ) strcpy( ContentType , "application/x-a11" ) ;
	else if ( ! strncasecmp( ExtName , ".acp" , strlen(".acp") ) ) strcpy( ContentType , "audio/x-mei-aac" ) ;
	else if ( ! strncasecmp( ExtName , ".ai" , strlen(".ai") ) ) strcpy( ContentType , "application/postscript" ) ;
	else if ( ! strncasecmp( ExtName , ".aif" , strlen(".aif") ) ) strcpy( ContentType , "audio/aiff" ) ;
	else if ( ! strncasecmp( ExtName , ".aifc" , strlen(".aifc") ) ) strcpy( ContentType , "audio/aiff" ) ;
	else if ( ! strncasecmp( ExtName , ".aiff" , strlen(".aiff") ) ) strcpy( ContentType , "audio/aiff" ) ;
	else if ( ! strncasecmp( ExtName , ".anv" , strlen(".anv") ) ) strcpy( ContentType , "application/x-anv" ) ;
	else if ( ! strncasecmp( ExtName , ".asa" , strlen(".asa") ) ) strcpy( ContentType , "text/asa" ) ;
	else if ( ! strncasecmp( ExtName , ".asf" , strlen(".asf") ) ) strcpy( ContentType , "video/x-ms-asf" ) ;
	else if ( ! strncasecmp( ExtName , ".asp" , strlen(".asp") ) ) strcpy( ContentType , "text/asp" ) ;
	else if ( ! strncasecmp( ExtName , ".asx" , strlen(".asx") ) ) strcpy( ContentType , "video/x-ms-asf" ) ;
	else if ( ! strncasecmp( ExtName , ".au" , strlen(".au") ) ) strcpy( ContentType , "audio/basic" ) ;
	else if ( ! strncasecmp( ExtName , ".avi" , strlen(".avi") ) ) strcpy( ContentType , "video/avi" ) ;
	else if ( ! strncasecmp( ExtName , ".awf" , strlen(".awf") ) ) strcpy( ContentType , "application/vnd.adobe.workflow" ) ;
	else if ( ! strncasecmp( ExtName , ".biz" , strlen(".biz") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".bmp" , strlen(".bmp") ) ) strcpy( ContentType , "application/x-bmp" ) ;
	else if ( ! strncasecmp( ExtName , ".bot" , strlen(".bot") ) ) strcpy( ContentType , "application/x-bot" ) ;
	else if ( ! strncasecmp( ExtName , ".c4t" , strlen(".c4t") ) ) strcpy( ContentType , "application/x-c4t" ) ;
	else if ( ! strncasecmp( ExtName , ".c90" , strlen(".c90") ) ) strcpy( ContentType , "application/x-c90" ) ;
	else if ( ! strncasecmp( ExtName , ".cal" , strlen(".cal") ) ) strcpy( ContentType , "application/x-cals" ) ;
	else if ( ! strncasecmp( ExtName , ".cat" , strlen(".cat") ) ) strcpy( ContentType , "application/s-pki.seccat" ) ;
	else if ( ! strncasecmp( ExtName , ".cdf" , strlen(".cdf") ) ) strcpy( ContentType , "application/x-netcdf" ) ;
	else if ( ! strncasecmp( ExtName , ".cdr" , strlen(".cdr") ) ) strcpy( ContentType , "application/x-cdr" ) ;
	else if ( ! strncasecmp( ExtName , ".cel" , strlen(".cel") ) ) strcpy( ContentType , "application/x-cel" ) ;
	else if ( ! strncasecmp( ExtName , ".cer" , strlen(".cer") ) ) strcpy( ContentType , "application/x-x509-ca-cert" ) ;
	else if ( ! strncasecmp( ExtName , ".cg4" , strlen(".cg4") ) ) strcpy( ContentType , "application/x-g4" ) ;
	else if ( ! strncasecmp( ExtName , ".cgm" , strlen(".cgm") ) ) strcpy( ContentType , "application/x-cgm" ) ;
	else if ( ! strncasecmp( ExtName , ".cit" , strlen(".cit") ) ) strcpy( ContentType , "application/x-cit" ) ;
	else if ( ! strncasecmp( ExtName , ".class" , strlen(".class") ) ) strcpy( ContentType , "java/*" ) ;
	else if ( ! strncasecmp( ExtName , ".cml" , strlen(".cml") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".cmp" , strlen(".cmp") ) ) strcpy( ContentType , "application/x-cmp" ) ;
	else if ( ! strncasecmp( ExtName , ".cmx" , strlen(".cmx") ) ) strcpy( ContentType , "application/x-cmx" ) ;
	else if ( ! strncasecmp( ExtName , ".cot" , strlen(".cot") ) ) strcpy( ContentType , "application/x-cot" ) ;
	else if ( ! strncasecmp( ExtName , ".crl" , strlen(".crl") ) ) strcpy( ContentType , "application/pkix-crl" ) ;
	else if ( ! strncasecmp( ExtName , ".crt" , strlen(".crt") ) ) strcpy( ContentType , "application/x-x509-ca-cert" ) ;
	else if ( ! strncasecmp( ExtName , ".csi" , strlen(".csi") ) ) strcpy( ContentType , "application/x-csi" ) ;
	else if ( ! strncasecmp( ExtName , ".css" , strlen(".css") ) ) strcpy( ContentType , "text/css" ) ;
	else if ( ! strncasecmp( ExtName , ".cut" , strlen(".cut") ) ) strcpy( ContentType , "application/x-cut" ) ;
	else if ( ! strncasecmp( ExtName , ".dbf" , strlen(".dbf") ) ) strcpy( ContentType , "application/x-dbf" ) ;
	else if ( ! strncasecmp( ExtName , ".dbm" , strlen(".dbm") ) ) strcpy( ContentType , "application/x-dbm" ) ;
	else if ( ! strncasecmp( ExtName , ".dbx" , strlen(".dbx") ) ) strcpy( ContentType , "application/x-dbx" ) ;
	else if ( ! strncasecmp( ExtName , ".dcd" , strlen(".dcd") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".dcx" , strlen(".dcx") ) ) strcpy( ContentType , "application/x-dcx" ) ;
	else if ( ! strncasecmp( ExtName , ".der" , strlen(".der") ) ) strcpy( ContentType , "application/x-x509-ca-cert" ) ;
	else if ( ! strncasecmp( ExtName , ".dgn" , strlen(".dgn") ) ) strcpy( ContentType , "application/x-dgn" ) ;
	else if ( ! strncasecmp( ExtName , ".dib" , strlen(".dib") ) ) strcpy( ContentType , "application/x-dib" ) ;
	else if ( ! strncasecmp( ExtName , ".dll" , strlen(".dll") ) ) strcpy( ContentType , "application/x-msdownload" ) ;
	else if ( ! strncasecmp( ExtName , ".doc" , strlen(".doc") ) ) strcpy( ContentType , "application/msword" ) ;
	else if ( ! strncasecmp( ExtName , ".dot" , strlen(".dot") ) ) strcpy( ContentType , "application/msword" ) ;
	else if ( ! strncasecmp( ExtName , ".drw" , strlen(".drw") ) ) strcpy( ContentType , "application/x-drw" ) ;
	else if ( ! strncasecmp( ExtName , ".dtd" , strlen(".dtd") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".dwf" , strlen(".dwf") ) ) strcpy( ContentType , "Model/vnd.dwf" ) ;
	else if ( ! strncasecmp( ExtName , ".dwf" , strlen(".dwf") ) ) strcpy( ContentType , "application/x-dwf" ) ;
	else if ( ! strncasecmp( ExtName , ".dwg" , strlen(".dwg") ) ) strcpy( ContentType , "application/x-dwg" ) ;
	else if ( ! strncasecmp( ExtName , ".dxb" , strlen(".dxb") ) ) strcpy( ContentType , "application/x-dxb" ) ;
	else if ( ! strncasecmp( ExtName , ".dxf" , strlen(".dxf") ) ) strcpy( ContentType , "application/x-dxf" ) ;
	else if ( ! strncasecmp( ExtName , ".edn" , strlen(".edn") ) ) strcpy( ContentType , "application/vnd.adobe.edn" ) ;
	else if ( ! strncasecmp( ExtName , ".emf" , strlen(".emf") ) ) strcpy( ContentType , "application/x-emf" ) ;
	else if ( ! strncasecmp( ExtName , ".eml" , strlen(".eml") ) ) strcpy( ContentType , "message/rfc822" ) ;
	else if ( ! strncasecmp( ExtName , ".ent" , strlen(".ent") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".epi" , strlen(".epi") ) ) strcpy( ContentType , "application/x-epi" ) ;
	else if ( ! strncasecmp( ExtName , ".eps" , strlen(".eps") ) ) strcpy( ContentType , "application/x-ps" ) ;
	else if ( ! strncasecmp( ExtName , ".eps" , strlen(".eps") ) ) strcpy( ContentType , "application/postscript" ) ;
	else if ( ! strncasecmp( ExtName , ".etd" , strlen(".etd") ) ) strcpy( ContentType , "application/x-ebx" ) ;
	else if ( ! strncasecmp( ExtName , ".exe" , strlen(".exe") ) ) strcpy( ContentType , "application/x-msdownload" ) ;
	else if ( ! strncasecmp( ExtName , ".fax" , strlen(".fax") ) ) strcpy( ContentType , "image/fax" ) ;
	else if ( ! strncasecmp( ExtName , ".fdf" , strlen(".fdf") ) ) strcpy( ContentType , "application/vnd.fdf" ) ;
	else if ( ! strncasecmp( ExtName , ".fif" , strlen(".fif") ) ) strcpy( ContentType , "application/fractals" ) ;
	else if ( ! strncasecmp( ExtName , ".fo" , strlen(".fo") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".frm" , strlen(".frm") ) ) strcpy( ContentType , "application/x-frm" ) ;
	else if ( ! strncasecmp( ExtName , ".g4" , strlen(".g4") ) ) strcpy( ContentType , "application/x-g4" ) ;
	else if ( ! strncasecmp( ExtName , ".gbr" , strlen(".gbr") ) ) strcpy( ContentType , "application/x-gbr" ) ;
	else if ( ! strncasecmp( ExtName , ".gcd" , strlen(".gcd") ) ) strcpy( ContentType , "application/x-gcd" ) ;
	else if ( ! strncasecmp( ExtName , ".gif" , strlen(".gif") ) ) strcpy( ContentType , "image/gif" ) ;
	else if ( ! strncasecmp( ExtName , ".gl2" , strlen(".gl2") ) ) strcpy( ContentType , "application/x-gl2" ) ;
	else if ( ! strncasecmp( ExtName , ".gp4" , strlen(".gp4") ) ) strcpy( ContentType , "application/x-gp4" ) ;
	else if ( ! strncasecmp( ExtName , ".hgl" , strlen(".hgl") ) ) strcpy( ContentType , "application/x-hgl" ) ;
	else if ( ! strncasecmp( ExtName , ".hmr" , strlen(".hmr") ) ) strcpy( ContentType , "application/x-hmr" ) ;
	else if ( ! strncasecmp( ExtName , ".hpg" , strlen(".hpg") ) ) strcpy( ContentType , "application/x-hpgl" ) ;
	else if ( ! strncasecmp( ExtName , ".hpl" , strlen(".hpl") ) ) strcpy( ContentType , "application/x-hpl" ) ;
	else if ( ! strncasecmp( ExtName , ".hqx" , strlen(".hqx") ) ) strcpy( ContentType , "application/mac-binhex40" ) ;
	else if ( ! strncasecmp( ExtName , ".hrf" , strlen(".hrf") ) ) strcpy( ContentType , "application/x-hrf" ) ;
	else if ( ! strncasecmp( ExtName , ".hta" , strlen(".hta") ) ) strcpy( ContentType , "application/hta" ) ;
	else if ( ! strncasecmp( ExtName , ".htc" , strlen(".htc") ) ) strcpy( ContentType , "text/x-component" ) ;
	else if ( ! strncasecmp( ExtName , ".htm" , strlen(".htm") ) ) strcpy( ContentType , "text/html" ) ;
	else if ( ! strncasecmp( ExtName , ".html" , strlen(".html") ) ) strcpy( ContentType , "text/html" ) ;
	else if ( ! strncasecmp( ExtName , ".htt" , strlen(".htt") ) ) strcpy( ContentType , "text/webviewhtml" ) ;
	else if ( ! strncasecmp( ExtName , ".htx" , strlen(".htx") ) ) strcpy( ContentType , "text/html" ) ;
	else if ( ! strncasecmp( ExtName , ".icb" , strlen(".icb") ) ) strcpy( ContentType , "application/x-icb" ) ;
	else if ( ! strncasecmp( ExtName , ".ico" , strlen(".ico") ) ) strcpy( ContentType , "image/x-icon" ) ;
	else if ( ! strncasecmp( ExtName , ".ico" , strlen(".ico") ) ) strcpy( ContentType , "application/x-ico" ) ;
	else if ( ! strncasecmp( ExtName , ".iff" , strlen(".iff") ) ) strcpy( ContentType , "application/x-iff" ) ;
	else if ( ! strncasecmp( ExtName , ".ig4" , strlen(".ig4") ) ) strcpy( ContentType , "application/x-g4" ) ;
	else if ( ! strncasecmp( ExtName , ".igs" , strlen(".igs") ) ) strcpy( ContentType , "application/x-igs" ) ;
	else if ( ! strncasecmp( ExtName , ".iii" , strlen(".iii") ) ) strcpy( ContentType , "application/x-iphone" ) ;
	else if ( ! strncasecmp( ExtName , ".img" , strlen(".img") ) ) strcpy( ContentType , "application/x-img" ) ;
	else if ( ! strncasecmp( ExtName , ".ins" , strlen(".ins") ) ) strcpy( ContentType , "application/x-internet-signup" ) ;
	else if ( ! strncasecmp( ExtName , ".isp" , strlen(".isp") ) ) strcpy( ContentType , "application/x-internet-signup" ) ;
	else if ( ! strncasecmp( ExtName , ".IVF" , strlen(".IVF") ) ) strcpy( ContentType , "video/x-ivf" ) ;
	else if ( ! strncasecmp( ExtName , ".java" , strlen(".java") ) ) strcpy( ContentType , "java/*" ) ;
	else if ( ! strncasecmp( ExtName , ".jfif" , strlen(".jfif") ) ) strcpy( ContentType , "image/jpeg" ) ;
	else if ( ! strncasecmp( ExtName , ".jpe" , strlen(".jpe") ) ) strcpy( ContentType , "image/jpeg" ) ;
	else if ( ! strncasecmp( ExtName , ".jpe" , strlen(".jpe") ) ) strcpy( ContentType , "application/x-jpe" ) ;
	else if ( ! strncasecmp( ExtName , ".jpeg" , strlen(".jpeg") ) ) strcpy( ContentType , "image/jpeg" ) ;
	else if ( ! strncasecmp( ExtName , ".jpg" , strlen(".jpg") ) ) strcpy( ContentType , "image/jpeg" ) ;
	else if ( ! strncasecmp( ExtName , ".jpg" , strlen(".jpg") ) ) strcpy( ContentType , "application/x-jpg" ) ;
	else if ( ! strncasecmp( ExtName , ".js" , strlen(".js") ) ) strcpy( ContentType , "application/x-javascript" ) ;
	else if ( ! strncasecmp( ExtName , ".jsp" , strlen(".jsp") ) ) strcpy( ContentType , "text/html" ) ;
	else if ( ! strncasecmp( ExtName , ".la1" , strlen(".la1") ) ) strcpy( ContentType , "audio/x-liquid-file" ) ;
	else if ( ! strncasecmp( ExtName , ".lar" , strlen(".lar") ) ) strcpy( ContentType , "application/x-laplayer-reg" ) ;
	else if ( ! strncasecmp( ExtName , ".latex" , strlen(".latex") ) ) strcpy( ContentType , "application/x-latex" ) ;
	else if ( ! strncasecmp( ExtName , ".lavs" , strlen(".lavs") ) ) strcpy( ContentType , "audio/x-liquid-secure" ) ;
	else if ( ! strncasecmp( ExtName , ".lbm" , strlen(".lbm") ) ) strcpy( ContentType , "application/x-lbm" ) ;
	else if ( ! strncasecmp( ExtName , ".lmsff" , strlen(".lmsff") ) ) strcpy( ContentType , "audio/x-la-lms" ) ;
	else if ( ! strncasecmp( ExtName , ".ls" , strlen(".ls") ) ) strcpy( ContentType , "application/x-javascript" ) ;
	else if ( ! strncasecmp( ExtName , ".ltr" , strlen(".ltr") ) ) strcpy( ContentType , "application/x-ltr" ) ;
	else if ( ! strncasecmp( ExtName , ".m1v" , strlen(".m1v") ) ) strcpy( ContentType , "video/x-mpeg" ) ;
	else if ( ! strncasecmp( ExtName , ".m2v" , strlen(".m2v") ) ) strcpy( ContentType , "video/x-mpeg" ) ;
	else if ( ! strncasecmp( ExtName , ".m3u" , strlen(".m3u") ) ) strcpy( ContentType , "audio/mpegurl" ) ;
	else if ( ! strncasecmp( ExtName , ".m4e" , strlen(".m4e") ) ) strcpy( ContentType , "video/mpeg4" ) ;
	else if ( ! strncasecmp( ExtName , ".mac" , strlen(".mac") ) ) strcpy( ContentType , "application/x-mac" ) ;
	else if ( ! strncasecmp( ExtName , ".man" , strlen(".man") ) ) strcpy( ContentType , "application/x-troff-man" ) ;
	else if ( ! strncasecmp( ExtName , ".math" , strlen(".math") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".mdb" , strlen(".mdb") ) ) strcpy( ContentType , "application/msaccess" ) ;
	else if ( ! strncasecmp( ExtName , ".mdb" , strlen(".mdb") ) ) strcpy( ContentType , "application/x-mdb" ) ;
	else if ( ! strncasecmp( ExtName , ".mfp" , strlen(".mfp") ) ) strcpy( ContentType , "application/x-shockwave-flash" ) ;
	else if ( ! strncasecmp( ExtName , ".mht" , strlen(".mht") ) ) strcpy( ContentType , "message/rfc822" ) ;
	else if ( ! strncasecmp( ExtName , ".mhtml" , strlen(".mhtml") ) ) strcpy( ContentType , "message/rfc822" ) ;
	else if ( ! strncasecmp( ExtName , ".mi" , strlen(".mi") ) ) strcpy( ContentType , "application/x-mi" ) ;
	else if ( ! strncasecmp( ExtName , ".mid" , strlen(".mid") ) ) strcpy( ContentType , "audio/mid" ) ;
	else if ( ! strncasecmp( ExtName , ".midi" , strlen(".midi") ) ) strcpy( ContentType , "audio/mid" ) ;
	else if ( ! strncasecmp( ExtName , ".mil" , strlen(".mil") ) ) strcpy( ContentType , "application/x-mil" ) ;
	else if ( ! strncasecmp( ExtName , ".mml" , strlen(".mml") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".mnd" , strlen(".mnd") ) ) strcpy( ContentType , "audio/x-musicnet-download" ) ;
	else if ( ! strncasecmp( ExtName , ".mns" , strlen(".mns") ) ) strcpy( ContentType , "audio/x-musicnet-stream" ) ;
	else if ( ! strncasecmp( ExtName , ".mocha" , strlen(".mocha") ) ) strcpy( ContentType , "application/x-javascript" ) ;
	else if ( ! strncasecmp( ExtName , ".movie" , strlen(".movie") ) ) strcpy( ContentType , "video/x-sgi-movie" ) ;
	else if ( ! strncasecmp( ExtName , ".mp1" , strlen(".mp1") ) ) strcpy( ContentType , "audio/mp1" ) ;
	else if ( ! strncasecmp( ExtName , ".mp2" , strlen(".mp2") ) ) strcpy( ContentType , "audio/mp2" ) ;
	else if ( ! strncasecmp( ExtName , ".mp2v" , strlen(".mp2v") ) ) strcpy( ContentType , "video/mpeg" ) ;
	else if ( ! strncasecmp( ExtName , ".mp3" , strlen(".mp3") ) ) strcpy( ContentType , "audio/mpeg" ) ;
	else if ( ! strncasecmp( ExtName , ".mp4" , strlen(".mp4") ) ) strcpy( ContentType , "video/mp4" ) ;
	else if ( ! strncasecmp( ExtName , ".mpa" , strlen(".mpa") ) ) strcpy( ContentType , "video/x-mpg" ) ;
	else if ( ! strncasecmp( ExtName , ".mpd" , strlen(".mpd") ) ) strcpy( ContentType , "application/-project" ) ;
	else if ( ! strncasecmp( ExtName , ".mpe" , strlen(".mpe") ) ) strcpy( ContentType , "video/x-mpeg" ) ;
	else if ( ! strncasecmp( ExtName , ".mpeg" , strlen(".mpeg") ) ) strcpy( ContentType , "video/mpg" ) ;
	else if ( ! strncasecmp( ExtName , ".mpg" , strlen(".mpg") ) ) strcpy( ContentType , "video/mpg" ) ;
	else if ( ! strncasecmp( ExtName , ".mpga" , strlen(".mpga") ) ) strcpy( ContentType , "audio/rn-mpeg" ) ;
	else if ( ! strncasecmp( ExtName , ".mpp" , strlen(".mpp") ) ) strcpy( ContentType , "application/-project" ) ;
	else if ( ! strncasecmp( ExtName , ".mps" , strlen(".mps") ) ) strcpy( ContentType , "video/x-mpeg" ) ;
	else if ( ! strncasecmp( ExtName , ".mpt" , strlen(".mpt") ) ) strcpy( ContentType , "application/-project" ) ;
	else if ( ! strncasecmp( ExtName , ".mpv" , strlen(".mpv") ) ) strcpy( ContentType , "video/mpg" ) ;
	else if ( ! strncasecmp( ExtName , ".mpv2" , strlen(".mpv2") ) ) strcpy( ContentType , "video/mpeg" ) ;
	else if ( ! strncasecmp( ExtName , ".mpw" , strlen(".mpw") ) ) strcpy( ContentType , "application/s-project" ) ;
	else if ( ! strncasecmp( ExtName , ".mpx" , strlen(".mpx") ) ) strcpy( ContentType , "application/-project" ) ;
	else if ( ! strncasecmp( ExtName , ".mtx" , strlen(".mtx") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".mxp" , strlen(".mxp") ) ) strcpy( ContentType , "application/x-mmxp" ) ;
	else if ( ! strncasecmp( ExtName , ".net" , strlen(".net") ) ) strcpy( ContentType , "image/pnetvue" ) ;
	else if ( ! strncasecmp( ExtName , ".nrf" , strlen(".nrf") ) ) strcpy( ContentType , "application/x-nrf" ) ;
	else if ( ! strncasecmp( ExtName , ".nws" , strlen(".nws") ) ) strcpy( ContentType , "message/rfc822" ) ;
	else if ( ! strncasecmp( ExtName , ".odc" , strlen(".odc") ) ) strcpy( ContentType , "text/x-ms-odc" ) ;
	else if ( ! strncasecmp( ExtName , ".out" , strlen(".out") ) ) strcpy( ContentType , "application/x-out" ) ;
	else if ( ! strncasecmp( ExtName , ".p10" , strlen(".p10") ) ) strcpy( ContentType , "application/pkcs10" ) ;
	else if ( ! strncasecmp( ExtName , ".p12" , strlen(".p12") ) ) strcpy( ContentType , "application/x-pkcs12" ) ;
	else if ( ! strncasecmp( ExtName , ".p7b" , strlen(".p7b") ) ) strcpy( ContentType , "application/x-pkcs7-certificates" ) ;
	else if ( ! strncasecmp( ExtName , ".p7c" , strlen(".p7c") ) ) strcpy( ContentType , "application/pkcs7-mime" ) ;
	else if ( ! strncasecmp( ExtName , ".p7m" , strlen(".p7m") ) ) strcpy( ContentType , "application/pkcs7-mime" ) ;
	else if ( ! strncasecmp( ExtName , ".p7r" , strlen(".p7r") ) ) strcpy( ContentType , "application/x-pkcs7-certreqresp" ) ;
	else if ( ! strncasecmp( ExtName , ".p7s" , strlen(".p7s") ) ) strcpy( ContentType , "application/pkcs7-signature" ) ;
	else if ( ! strncasecmp( ExtName , ".pc5" , strlen(".pc5") ) ) strcpy( ContentType , "application/x-pc5" ) ;
	else if ( ! strncasecmp( ExtName , ".pci" , strlen(".pci") ) ) strcpy( ContentType , "application/x-pci" ) ;
	else if ( ! strncasecmp( ExtName , ".pcl" , strlen(".pcl") ) ) strcpy( ContentType , "application/x-pcl" ) ;
	else if ( ! strncasecmp( ExtName , ".pcx" , strlen(".pcx") ) ) strcpy( ContentType , "application/x-pcx" ) ;
	else if ( ! strncasecmp( ExtName , ".pdf" , strlen(".pdf") ) ) strcpy( ContentType , "application/pdf" ) ;
	else if ( ! strncasecmp( ExtName , ".pdx" , strlen(".pdx") ) ) strcpy( ContentType , "application/vnd.adobe.pdx" ) ;
	else if ( ! strncasecmp( ExtName , ".pfx" , strlen(".pfx") ) ) strcpy( ContentType , "application/x-pkcs12" ) ;
	else if ( ! strncasecmp( ExtName , ".pgl" , strlen(".pgl") ) ) strcpy( ContentType , "application/x-pgl" ) ;
	else if ( ! strncasecmp( ExtName , ".pic" , strlen(".pic") ) ) strcpy( ContentType , "application/x-pic" ) ;
	else if ( ! strncasecmp( ExtName , ".pko" , strlen(".pko") ) ) strcpy( ContentType , "application-pki.pko" ) ;
	else if ( ! strncasecmp( ExtName , ".pl" , strlen(".pl") ) ) strcpy( ContentType , "application/x-perl" ) ;
	else if ( ! strncasecmp( ExtName , ".plg" , strlen(".plg") ) ) strcpy( ContentType , "text/html" ) ;
	else if ( ! strncasecmp( ExtName , ".pls" , strlen(".pls") ) ) strcpy( ContentType , "audio/scpls" ) ;
	else if ( ! strncasecmp( ExtName , ".plt" , strlen(".plt") ) ) strcpy( ContentType , "application/x-plt" ) ;
	else if ( ! strncasecmp( ExtName , ".png" , strlen(".png") ) ) strcpy( ContentType , "image/png" ) ;
	else if ( ! strncasecmp( ExtName , ".png" , strlen(".png") ) ) strcpy( ContentType , "application/x-png" ) ;
	else if ( ! strncasecmp( ExtName , ".pot" , strlen(".pot") ) ) strcpy( ContentType , "applications-powerpoint" ) ;
	else if ( ! strncasecmp( ExtName , ".ppa" , strlen(".ppa") ) ) strcpy( ContentType , "application/vs-powerpoint" ) ;
	else if ( ! strncasecmp( ExtName , ".ppm" , strlen(".ppm") ) ) strcpy( ContentType , "application/x-ppm" ) ;
	else if ( ! strncasecmp( ExtName , ".pps" , strlen(".pps") ) ) strcpy( ContentType , "application-powerpoint" ) ;
	else if ( ! strncasecmp( ExtName , ".ppt" , strlen(".ppt") ) ) strcpy( ContentType , "applications-powerpoint" ) ;
	else if ( ! strncasecmp( ExtName , ".ppt" , strlen(".ppt") ) ) strcpy( ContentType , "application/x-ppt" ) ;
	else if ( ! strncasecmp( ExtName , ".pr" , strlen(".pr") ) ) strcpy( ContentType , "application/x-pr" ) ;
	else if ( ! strncasecmp( ExtName , ".prf" , strlen(".prf") ) ) strcpy( ContentType , "application/pics-rules" ) ;
	else if ( ! strncasecmp( ExtName , ".prn" , strlen(".prn") ) ) strcpy( ContentType , "application/x-prn" ) ;
	else if ( ! strncasecmp( ExtName , ".prt" , strlen(".prt") ) ) strcpy( ContentType , "application/x-prt" ) ;
	else if ( ! strncasecmp( ExtName , ".ps" , strlen(".ps") ) ) strcpy( ContentType , "application/x-ps" ) ;
	else if ( ! strncasecmp( ExtName , ".ps" , strlen(".ps") ) ) strcpy( ContentType , "application/postscript" ) ;
	else if ( ! strncasecmp( ExtName , ".ptn" , strlen(".ptn") ) ) strcpy( ContentType , "application/x-ptn" ) ;
	else if ( ! strncasecmp( ExtName , ".pwz" , strlen(".pwz") ) ) strcpy( ContentType , "application/powerpoint" ) ;
	else if ( ! strncasecmp( ExtName , ".r3t" , strlen(".r3t") ) ) strcpy( ContentType , "text/vnd.rn-realtext3d" ) ;
	else if ( ! strncasecmp( ExtName , ".ra" , strlen(".ra") ) ) strcpy( ContentType , "audio/vnd.rn-realaudio" ) ;
	else if ( ! strncasecmp( ExtName , ".ram" , strlen(".ram") ) ) strcpy( ContentType , "audio/x-pn-realaudio" ) ;
	else if ( ! strncasecmp( ExtName , ".ras" , strlen(".ras") ) ) strcpy( ContentType , "application/x-ras" ) ;
	else if ( ! strncasecmp( ExtName , ".rat" , strlen(".rat") ) ) strcpy( ContentType , "application/rat-file" ) ;
	else if ( ! strncasecmp( ExtName , ".rdf" , strlen(".rdf") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".rec" , strlen(".rec") ) ) strcpy( ContentType , "application/vnd.rn-recording" ) ;
	else if ( ! strncasecmp( ExtName , ".red" , strlen(".red") ) ) strcpy( ContentType , "application/x-red" ) ;
	else if ( ! strncasecmp( ExtName , ".rgb" , strlen(".rgb") ) ) strcpy( ContentType , "application/x-rgb" ) ;
	else if ( ! strncasecmp( ExtName , ".rjs" , strlen(".rjs") ) ) strcpy( ContentType , "application/vnd.rn-realsystem-rjs" ) ;
	else if ( ! strncasecmp( ExtName , ".rjt" , strlen(".rjt") ) ) strcpy( ContentType , "application/vnd.rn-realsystem-rjt" ) ;
	else if ( ! strncasecmp( ExtName , ".rlc" , strlen(".rlc") ) ) strcpy( ContentType , "application/x-rlc" ) ;
	else if ( ! strncasecmp( ExtName , ".rle" , strlen(".rle") ) ) strcpy( ContentType , "application/x-rle" ) ;
	else if ( ! strncasecmp( ExtName , ".rm" , strlen(".rm") ) ) strcpy( ContentType , "application/vnd.rn-realmedia" ) ;
	else if ( ! strncasecmp( ExtName , ".rmf" , strlen(".rmf") ) ) strcpy( ContentType , "application/vnd.adobe.rmf" ) ;
	else if ( ! strncasecmp( ExtName , ".rmi" , strlen(".rmi") ) ) strcpy( ContentType , "audio/mid" ) ;
	else if ( ! strncasecmp( ExtName , ".rmj" , strlen(".rmj") ) ) strcpy( ContentType , "application/vnd.rn-realsystem-rmj" ) ;
	else if ( ! strncasecmp( ExtName , ".rmm" , strlen(".rmm") ) ) strcpy( ContentType , "audio/x-pn-realaudio" ) ;
	else if ( ! strncasecmp( ExtName , ".rmp" , strlen(".rmp") ) ) strcpy( ContentType , "application/vnd.rn-rn_music_package" ) ;
	else if ( ! strncasecmp( ExtName , ".rms" , strlen(".rms") ) ) strcpy( ContentType , "application/vnd.rn-realmedia-secure" ) ;
	else if ( ! strncasecmp( ExtName , ".rmvb" , strlen(".rmvb") ) ) strcpy( ContentType , "application/vnd.rn-realmedia-vbr" ) ;
	else if ( ! strncasecmp( ExtName , ".rmx" , strlen(".rmx") ) ) strcpy( ContentType , "application/vnd.rn-realsystem-rmx" ) ;
	else if ( ! strncasecmp( ExtName , ".rnx" , strlen(".rnx") ) ) strcpy( ContentType , "application/vnd.rn-realplayer" ) ;
	else if ( ! strncasecmp( ExtName , ".rp" , strlen(".rp") ) ) strcpy( ContentType , "image/vnd.rn-realpix" ) ;
	else if ( ! strncasecmp( ExtName , ".rpm" , strlen(".rpm") ) ) strcpy( ContentType , "audio/x-pn-realaudio-plugin" ) ;
	else if ( ! strncasecmp( ExtName , ".rsml" , strlen(".rsml") ) ) strcpy( ContentType , "application/vnd.rn-rsml" ) ;
	else if ( ! strncasecmp( ExtName , ".rt" , strlen(".rt") ) ) strcpy( ContentType , "text/vnd.rn-realtext" ) ;
	else if ( ! strncasecmp( ExtName , ".rtf" , strlen(".rtf") ) ) strcpy( ContentType , "application/msword" ) ;
	else if ( ! strncasecmp( ExtName , ".rtf" , strlen(".rtf") ) ) strcpy( ContentType , "application/x-rtf" ) ;
	else if ( ! strncasecmp( ExtName , ".rv" , strlen(".rv") ) ) strcpy( ContentType , "video/vnd.rn-realvideo" ) ;
	else if ( ! strncasecmp( ExtName , ".sam" , strlen(".sam") ) ) strcpy( ContentType , "application/x-sam" ) ;
	else if ( ! strncasecmp( ExtName , ".sat" , strlen(".sat") ) ) strcpy( ContentType , "application/x-sat" ) ;
	else if ( ! strncasecmp( ExtName , ".sdp" , strlen(".sdp") ) ) strcpy( ContentType , "application/sdp" ) ;
	else if ( ! strncasecmp( ExtName , ".sdw" , strlen(".sdw") ) ) strcpy( ContentType , "application/x-sdw" ) ;
	else if ( ! strncasecmp( ExtName , ".sit" , strlen(".sit") ) ) strcpy( ContentType , "application/x-stuffit" ) ;
	else if ( ! strncasecmp( ExtName , ".slb" , strlen(".slb") ) ) strcpy( ContentType , "application/x-slb" ) ;
	else if ( ! strncasecmp( ExtName , ".sld" , strlen(".sld") ) ) strcpy( ContentType , "application/x-sld" ) ;
	else if ( ! strncasecmp( ExtName , ".slk" , strlen(".slk") ) ) strcpy( ContentType , "drawing/x-slk" ) ;
	else if ( ! strncasecmp( ExtName , ".smi" , strlen(".smi") ) ) strcpy( ContentType , "application/smil" ) ;
	else if ( ! strncasecmp( ExtName , ".smil" , strlen(".smil") ) ) strcpy( ContentType , "application/smil" ) ;
	else if ( ! strncasecmp( ExtName , ".smk" , strlen(".smk") ) ) strcpy( ContentType , "application/x-smk" ) ;
	else if ( ! strncasecmp( ExtName , ".snd" , strlen(".snd") ) ) strcpy( ContentType , "audio/basic" ) ;
	else if ( ! strncasecmp( ExtName , ".sol" , strlen(".sol") ) ) strcpy( ContentType , "text/plain" ) ;
	else if ( ! strncasecmp( ExtName , ".sor" , strlen(".sor") ) ) strcpy( ContentType , "text/plain" ) ;
	else if ( ! strncasecmp( ExtName , ".spc" , strlen(".spc") ) ) strcpy( ContentType , "application/x-pkcs7-certificates" ) ;
	else if ( ! strncasecmp( ExtName , ".spl" , strlen(".spl") ) ) strcpy( ContentType , "application/futuresplash" ) ;
	else if ( ! strncasecmp( ExtName , ".spp" , strlen(".spp") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".ssm" , strlen(".ssm") ) ) strcpy( ContentType , "application/streamingmedia" ) ;
	else if ( ! strncasecmp( ExtName , ".sst" , strlen(".sst") ) ) strcpy( ContentType , "application-pki.certstore" ) ;
	else if ( ! strncasecmp( ExtName , ".stl" , strlen(".stl") ) ) strcpy( ContentType , "application/-pki.stl" ) ;
	else if ( ! strncasecmp( ExtName , ".stm" , strlen(".stm") ) ) strcpy( ContentType , "text/html" ) ;
	else if ( ! strncasecmp( ExtName , ".sty" , strlen(".sty") ) ) strcpy( ContentType , "application/x-sty" ) ;
	else if ( ! strncasecmp( ExtName , ".svg" , strlen(".svg") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".swf" , strlen(".swf") ) ) strcpy( ContentType , "application/x-shockwave-flash" ) ;
	else if ( ! strncasecmp( ExtName , ".tdf" , strlen(".tdf") ) ) strcpy( ContentType , "application/x-tdf" ) ;
	else if ( ! strncasecmp( ExtName , ".tg4" , strlen(".tg4") ) ) strcpy( ContentType , "application/x-tg4" ) ;
	else if ( ! strncasecmp( ExtName , ".tga" , strlen(".tga") ) ) strcpy( ContentType , "application/x-tga" ) ;
	else if ( ! strncasecmp( ExtName , ".tif" , strlen(".tif") ) ) strcpy( ContentType , "image/tiff" ) ;
	else if ( ! strncasecmp( ExtName , ".tif" , strlen(".tif") ) ) strcpy( ContentType , "application/x-tif" ) ;
	else if ( ! strncasecmp( ExtName , ".tiff" , strlen(".tiff") ) ) strcpy( ContentType , "image/tiff" ) ;
	else if ( ! strncasecmp( ExtName , ".tld" , strlen(".tld") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".top" , strlen(".top") ) ) strcpy( ContentType , "drawing/x-top" ) ;
	else if ( ! strncasecmp( ExtName , ".torrent" , strlen(".torrent") ) ) strcpy( ContentType , "application/x-bittorrent" ) ;
	else if ( ! strncasecmp( ExtName , ".tsd" , strlen(".tsd") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".txt" , strlen(".txt") ) ) strcpy( ContentType , "text/plain" ) ;
	else if ( ! strncasecmp( ExtName , ".uin" , strlen(".uin") ) ) strcpy( ContentType , "application/x-icq" ) ;
	else if ( ! strncasecmp( ExtName , ".uls" , strlen(".uls") ) ) strcpy( ContentType , "text/iuls" ) ;
	else if ( ! strncasecmp( ExtName , ".vcf" , strlen(".vcf") ) ) strcpy( ContentType , "text/x-vcard" ) ;
	else if ( ! strncasecmp( ExtName , ".vda" , strlen(".vda") ) ) strcpy( ContentType , "application/x-vda" ) ;
	else if ( ! strncasecmp( ExtName , ".vdx" , strlen(".vdx") ) ) strcpy( ContentType , "application/vnd.visio" ) ;
	else if ( ! strncasecmp( ExtName , ".vml" , strlen(".vml") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".vpg" , strlen(".vpg") ) ) strcpy( ContentType , "application/x-vpeg005" ) ;
	else if ( ! strncasecmp( ExtName , ".vsd" , strlen(".vsd") ) ) strcpy( ContentType , "application/vnd.visio" ) ;
	else if ( ! strncasecmp( ExtName , ".vsd" , strlen(".vsd") ) ) strcpy( ContentType , "application/x-vsd" ) ;
	else if ( ! strncasecmp( ExtName , ".vss" , strlen(".vss") ) ) strcpy( ContentType , "application/vnd.visio" ) ;
	else if ( ! strncasecmp( ExtName , ".vst" , strlen(".vst") ) ) strcpy( ContentType , "application/vnd.visio" ) ;
	else if ( ! strncasecmp( ExtName , ".vst" , strlen(".vst") ) ) strcpy( ContentType , "application/x-vst" ) ;
	else if ( ! strncasecmp( ExtName , ".vsw" , strlen(".vsw") ) ) strcpy( ContentType , "application/vnd.visio" ) ;
	else if ( ! strncasecmp( ExtName , ".vsx" , strlen(".vsx") ) ) strcpy( ContentType , "application/vnd.visio" ) ;
	else if ( ! strncasecmp( ExtName , ".vtx" , strlen(".vtx") ) ) strcpy( ContentType , "application/vnd.visio" ) ;
	else if ( ! strncasecmp( ExtName , ".vxml" , strlen(".vxml") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".wav" , strlen(".wav") ) ) strcpy( ContentType , "audio/wav" ) ;
	else if ( ! strncasecmp( ExtName , ".wax" , strlen(".wax") ) ) strcpy( ContentType , "audio/x-ms-wax" ) ;
	else if ( ! strncasecmp( ExtName , ".wb1" , strlen(".wb1") ) ) strcpy( ContentType , "application/x-wb1" ) ;
	else if ( ! strncasecmp( ExtName , ".wb2" , strlen(".wb2") ) ) strcpy( ContentType , "application/x-wb2" ) ;
	else if ( ! strncasecmp( ExtName , ".wb3" , strlen(".wb3") ) ) strcpy( ContentType , "application/x-wb3" ) ;
	else if ( ! strncasecmp( ExtName , ".wbmp" , strlen(".wbmp") ) ) strcpy( ContentType , "image/vnd.wap.wbmp" ) ;
	else if ( ! strncasecmp( ExtName , ".wiz" , strlen(".wiz") ) ) strcpy( ContentType , "application/msword" ) ;
	else if ( ! strncasecmp( ExtName , ".wk3" , strlen(".wk3") ) ) strcpy( ContentType , "application/x-wk3" ) ;
	else if ( ! strncasecmp( ExtName , ".wk4" , strlen(".wk4") ) ) strcpy( ContentType , "application/x-wk4" ) ;
	else if ( ! strncasecmp( ExtName , ".wkq" , strlen(".wkq") ) ) strcpy( ContentType , "application/x-wkq" ) ;
	else if ( ! strncasecmp( ExtName , ".wks" , strlen(".wks") ) ) strcpy( ContentType , "application/x-wks" ) ;
	else if ( ! strncasecmp( ExtName , ".wm" , strlen(".wm") ) ) strcpy( ContentType , "video/x-ms-wm" ) ;
	else if ( ! strncasecmp( ExtName , ".wma" , strlen(".wma") ) ) strcpy( ContentType , "audio/x-ms-wma" ) ;
	else if ( ! strncasecmp( ExtName , ".wmd" , strlen(".wmd") ) ) strcpy( ContentType , "application/x-ms-wmd" ) ;
	else if ( ! strncasecmp( ExtName , ".wmf" , strlen(".wmf") ) ) strcpy( ContentType , "application/x-wmf" ) ;
	else if ( ! strncasecmp( ExtName , ".wml" , strlen(".wml") ) ) strcpy( ContentType , "text/vnd.wap.wml" ) ;
	else if ( ! strncasecmp( ExtName , ".wmv" , strlen(".wmv") ) ) strcpy( ContentType , "video/x-ms-wmv" ) ;
	else if ( ! strncasecmp( ExtName , ".wmx" , strlen(".wmx") ) ) strcpy( ContentType , "video/x-ms-wmx" ) ;
	else if ( ! strncasecmp( ExtName , ".wmz" , strlen(".wmz") ) ) strcpy( ContentType , "application/x-ms-wmz" ) ;
	else if ( ! strncasecmp( ExtName , ".wp6" , strlen(".wp6") ) ) strcpy( ContentType , "application/x-wp6" ) ;
	else if ( ! strncasecmp( ExtName , ".wpd" , strlen(".wpd") ) ) strcpy( ContentType , "application/x-wpd" ) ;
	else if ( ! strncasecmp( ExtName , ".wpg" , strlen(".wpg") ) ) strcpy( ContentType , "application/x-wpg" ) ;
	else if ( ! strncasecmp( ExtName , ".wpl" , strlen(".wpl") ) ) strcpy( ContentType , "application/-wpl" ) ;
	else if ( ! strncasecmp( ExtName , ".wq1" , strlen(".wq1") ) ) strcpy( ContentType , "application/x-wq1" ) ;
	else if ( ! strncasecmp( ExtName , ".wr1" , strlen(".wr1") ) ) strcpy( ContentType , "application/x-wr1" ) ;
	else if ( ! strncasecmp( ExtName , ".wri" , strlen(".wri") ) ) strcpy( ContentType , "application/x-wri" ) ;
	else if ( ! strncasecmp( ExtName , ".wrk" , strlen(".wrk") ) ) strcpy( ContentType , "application/x-wrk" ) ;
	else if ( ! strncasecmp( ExtName , ".ws" , strlen(".ws") ) ) strcpy( ContentType , "application/x-ws" ) ;
	else if ( ! strncasecmp( ExtName , ".ws2" , strlen(".ws2") ) ) strcpy( ContentType , "application/x-ws" ) ;
	else if ( ! strncasecmp( ExtName , ".wsc" , strlen(".wsc") ) ) strcpy( ContentType , "text/scriptlet" ) ;
	else if ( ! strncasecmp( ExtName , ".wsdl" , strlen(".wsdl") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".wvx" , strlen(".wvx") ) ) strcpy( ContentType , "video/x-ms-wvx" ) ;
	else if ( ! strncasecmp( ExtName , ".xdp" , strlen(".xdp") ) ) strcpy( ContentType , "application/vnd.adobe.xdp" ) ;
	else if ( ! strncasecmp( ExtName , ".xdr" , strlen(".xdr") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".xfd" , strlen(".xfd") ) ) strcpy( ContentType , "application/vnd.adobe.xfd" ) ;
	else if ( ! strncasecmp( ExtName , ".xfdf" , strlen(".xfdf") ) ) strcpy( ContentType , "application/vnd.adobe.xfdf" ) ;
	else if ( ! strncasecmp( ExtName , ".xhtml" , strlen(".xhtml") ) ) strcpy( ContentType , "text/html" ) ;
	else if ( ! strncasecmp( ExtName , ".xls" , strlen(".xls") ) ) strcpy( ContentType , "application/-excel" ) ;
	else if ( ! strncasecmp( ExtName , ".xls" , strlen(".xls") ) ) strcpy( ContentType , "application/x-xls" ) ;
	else if ( ! strncasecmp( ExtName , ".xlw" , strlen(".xlw") ) ) strcpy( ContentType , "application/x-xlw" ) ;
	else if ( ! strncasecmp( ExtName , ".xml" , strlen(".xml") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".xpl" , strlen(".xpl") ) ) strcpy( ContentType , "audio/scpls" ) ;
	else if ( ! strncasecmp( ExtName , ".xq" , strlen(".xq") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".xql" , strlen(".xql") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".xquery" , strlen(".xquery") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".xsd" , strlen(".xsd") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".xsl" , strlen(".xsl") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".xslt" , strlen(".xslt") ) ) strcpy( ContentType , "text/xml" ) ;
	else if ( ! strncasecmp( ExtName , ".xwd" , strlen(".xwd") ) ) strcpy( ContentType , "application/x-xwd" ) ;
	else if ( ! strncasecmp( ExtName , ".x_b" , strlen(".x_b") ) ) strcpy( ContentType , "application/x-x_b" ) ;
	else if ( ! strncasecmp( ExtName , ".x_t" , strlen(".x_t") ) ) strcpy( ContentType , "application/x-x_t" ) ;
	else strcpy( ContentType , "application/octet-stream" ) ;

}

void GetMethodUrl( char * buffer , char * method , char * requestUrl )
{
	int i , len , k;
	len = strlen(buffer) ;
	for( i = 0 ; buffer[i] != ' ' && i < len ; i++ )
	{
		method[i] = buffer[i] ;
	}
	method[i] = '\0' ;
	for( k = 0, i++ ; buffer[i] != ' ' && i < len ; i++ , k++ )
	{
		requestUrl[k] = buffer[i] ;
	}
	requestUrl[k] = '\0' ;
}

void GetPara(char * buffer , char * dest , int start  )
{
	int i , k ;
	for( i = start , k =0 ; buffer[i] != '\0' && buffer[i] != '\r' && buffer[i] != '\n' ; i++ , k++ )
		dest[k] = buffer[i] ;
	dest[k] = '\0' ;
}

int Hex2Int(char * hex )
{
	int rst = 0 ;
	int tmp = 0 ;
	int i ;
	for( i = 0 ; i < (int)strlen(hex) ; i++ )
	{
		tmp = 0 ;
		switch(hex[i])
		{
		case 'A':
		case 'a':
			tmp = 10 ;
			break ;
		case 'B':
		case 'b':
			tmp = 11 ;
			break ;
		case 'C':
		case 'c':
			tmp = 12 ;
			break ;
		case 'D':
		case 'd':
			tmp = 13 ;
			break ;
		case 'E':
		case 'e':
			tmp = 14 ;
			break ;
		case 'F':
		case 'f':
			tmp = 15 ;
			break ;
		default:
			tmp = hex[i] - '0' ;
		}
		rst=rst*16+tmp ;
	}
//	printf("---> %s ==> %d \n " , hex , rst ) ;
	return rst ;
}


void DealPath(char * path )
{
	char str[1024] ;
	int ind ;
	char temp[10] ;
	int j = 0 ;
	for( ind = 0 ; ind < (int)(strlen(path)-2) ; ind++)
	{
		if( (path[ind] == '%') && ( (path[ind+1] >= '0' && path[ind+1] <= '9')|| (toupper( path[ind+1]) >='A' && toupper( path[ind+1]) <= 'Z')) && ( (path[ind+2] >= '0' && path[ind+2] <= '9')|| (toupper( path[ind+2]) >='A' && toupper( path[ind+2]) <= 'Z')))
		{
			temp[0] = path[ind+1] ;
			temp[1] = path[ind+2] ;
			temp[2] = '\0' ;
			str[j++] = Hex2Int(temp) ;
			ind = ind+2 ;
		}
		else
			str[j++] = path[ind] ;
	}
	if(path[ind-1] != '%' )
	{
		str[j++] = path[ind] ;
		str[j++] = path[ind+1] ;
	}
	str[j] = '\0' ;
	sprintf(path,"%s", str) ;

}

void DelRepeatedChar( char * buffer , char c )
{
	int i , j , k ;
	i = 0 ;
	
	while( buffer[i] != '\0' )
	{
		if( buffer[i] == c && buffer[i+1] == c) 
		{
			j = i;
			do
			{
				k=j+1;
				buffer[j] = buffer[k] ;
				j++ ;
			}while(buffer[j] != '\0') ;
		}
		else
		{
			i++ ;
		}
	}
	
}

int isFileExist(char * filePath)
{
	struct stat st;
	if( stat(filePath, &st) == -1 ) 
	{
		return 0 ;
	}
	if((st.st_mode & S_IFMT) == S_IFDIR)
	{
		return 2 ;
	}
	return 1 ;
}


void execCgiBin( char * FullPath , char * REQUEST_METHOD , char *  QUERY_STRING )
{
	int cgi_output[2];
	int cgi_input[2];
	pid_t pid;
	int status;
	int i;
	char c;
	int content_length = -1;
	
	content_length = atoi(CONTENT_LENGTH) ;
	
	if( strcasecmp( REQUEST_METHOD , "POST") == 0 && ( strlen(CONTENT_LENGTH) == 0 || content_length < 0  ) )
	{
		SendBadRequest() ;
		return ;
	}
	
	if (pipe(cgi_output) < 0)
	{
		SendInternalError();
		return;
	}
	if (pipe(cgi_input) < 0)
	{
		SendInternalError();
		return;
	}
	if( (pid = fork()) < 0 )
	{
		SendInternalError();
		return;
	}
	
	if (pid == 0)  /* child: CGI script */
	{
		char REQUEST_METHOD_ENV[100] , QUERY_STRING_ENV[1024] ;
		char HTTP_HOST_ENV[100] , HTTP_CACHE_CONTROL_ENV[100], HTTP_ACCEPT_ENCODING_ENV[100], HTTP_USER_AGENT_ENV[1024] , HTTP_ORIGIN_ENV[256] , HTTP_CONNECTION_ENV[100] , HTTP_ACCEPT_LANGUAGE_ENV[100] , HTTP_REFERER_ENV[1024] , HTTP_ACCEPT_ENV[200] , CONTENT_LENGTH_ENV[100] , CONTENT_TYPE_ENV[200]  , HTTP_COOKIE_ENV[1000];
		char  SCRIPT_FILENAME_ENV[256];
		
		dup2(cgi_output[1], 1);
		dup2(cgi_input[0], 0);
		close(cgi_output[0]);
		close(cgi_input[1]);
		
		sprintf(REQUEST_METHOD_ENV, "REQUEST_METHOD=%s", REQUEST_METHOD);
		putenv(REQUEST_METHOD_ENV);
		sprintf(QUERY_STRING_ENV, "QUERY_STRING=%s", QUERY_STRING);
		putenv(QUERY_STRING_ENV);
		sprintf(HTTP_HOST_ENV, "HTTP_HOST=%s", HTTP_HOST);
		putenv(HTTP_HOST_ENV);
		sprintf(HTTP_CACHE_CONTROL_ENV, "HTTP_CACHE_CONTROL=%s", HTTP_CACHE_CONTROL);
		putenv(HTTP_CACHE_CONTROL_ENV);
		sprintf(HTTP_ACCEPT_ENCODING_ENV, "HTTP_ACCEPT_ENCODING=%s", HTTP_ACCEPT_ENCODING);
		putenv(HTTP_ACCEPT_ENCODING_ENV);
		sprintf(HTTP_USER_AGENT_ENV, "HTTP_USER_AGENT=%s", HTTP_USER_AGENT);
		putenv(HTTP_USER_AGENT_ENV);
		sprintf(HTTP_ORIGIN_ENV, "HTTP_ORIGIN=%s", HTTP_ORIGIN);
		putenv(HTTP_ORIGIN_ENV);
		sprintf(HTTP_CONNECTION_ENV, "HTTP_CONNECTION=%s", HTTP_CONNECTION);
		putenv(HTTP_CONNECTION_ENV);
		sprintf(HTTP_ACCEPT_LANGUAGE_ENV, "HTTP_ACCEPT_LANGUAGE=%s", HTTP_ACCEPT_LANGUAGE);
		putenv(HTTP_ACCEPT_LANGUAGE_ENV);
		sprintf(HTTP_REFERER_ENV, "HTTP_REFERER=%s", HTTP_REFERER);
		putenv(HTTP_REFERER_ENV);
		sprintf(HTTP_ACCEPT_ENV, "HTTP_ACCEPT=%s", HTTP_ACCEPT);
		putenv(HTTP_ACCEPT_ENV);
		sprintf(CONTENT_LENGTH_ENV, "CONTENT_LENGTH=%s", CONTENT_LENGTH);
		putenv(CONTENT_LENGTH_ENV);
		sprintf(CONTENT_TYPE_ENV, "CONTENT_TYPE=%s", CONTENT_TYPE);
		putenv(CONTENT_TYPE_ENV);
		sprintf(HTTP_COOKIE_ENV, "HTTP_COOKIE=%s", HTTP_COOKIE);
		putenv(HTTP_COOKIE_ENV);
		
		sprintf(SCRIPT_FILENAME_ENV, "SCRIPT_FILENAME=%s", FullPath);
		putenv(SCRIPT_FILENAME_ENV);
		
		
		/*
		// not invalid
		char * PWD_ENV[256] ;
		sprintf(PWD_ENV, "%s", FullPath);
		char * p = rindex(PWD_ENV , '/') ;
		if( p != 0 ) p[1] = '\0' ;
		setenv("PWD" , PWD_ENV, 1 );
		*/
		
		execl(FullPath, FullPath, NULL);
		exit(0);
	}
	else
	{
		close(cgi_output[1]);
		close(cgi_input[0]);
		// read post string and sent to child 
		if (strcasecmp(REQUEST_METHOD, "POST") == 0)
		{
			for (i = 0; i < content_length; i++)
			{
				if( isHttpsProcess == 1 ) 
				{
					SSL_read(ssl_client, &c, 1);
				}
				else
				{
					recv(client_fd, &c, 1, 0);
				}
				write(cgi_input[1], &c, 1);
			}
			c = '\n' ; //add one '\n'
			write(cgi_input[1], &c, 1);
		}
		
		char buf[BUFFER_SIZE];
		sprintf( buf ,"HTTP/1.0 200 OK\r\nServer: %s\r\nConnection: close\r\n" , SERVER_VERSION );
		SendToClient(buf, strlen(buf));
		
		// read child result 
		//printf("CGI_RESULT(%d): BEGIN\n",client) ;
		while (read(cgi_output[0], &c, 1) > 0)
		{
			if( isHttpsProcess == 1 ) 
			{
				SSL_write(ssl_client, &c, 1);
			}
			else
			{
				send(client_fd, &c, 1, 0);
			}
		}
		//printf("CGI_RESULT(%d): END\n",client) ;
		
		close(cgi_output[0]);
		close(cgi_input[1]);
		waitpid(pid, &status, 0);
	}
}

void DealWithClient()
{
	
	char buffer[BUFFER_SIZE] ;
	int i , k , res ;
	int cgiFlag = 0 ;
	char FullPath[1024] ;
	struct stat st;
	char * str ;
	char * nstr ;
	int flag_exist ;
	char webSite[1024] ;

	struct sockaddr_in clientAddr;
	int addr_len = sizeof(clientAddr);
	

	
	getpeername(client_fd, (struct sockaddr *)&clientAddr , (socklen_t * )&addr_len);

	sprintf( logstring , "%s[%d] : %s:%d : ",isHttpsProcess == 1 ? "HTTPS":"HTTP", getpid(), inet_ntoa(clientAddr.sin_addr) , ntohs(clientAddr.sin_port) ) ;
	signal(SIGALRM, ChildProcessTimeOut);
	alarm(CONNECT_TIME_OUT);
	
	if( isHttpsProcess == 1 )
	{
		ssl_client = SSL_new(ctx); 
		SSL_set_fd(ssl_client, client_fd); 
		
		if ( SSL_accept(ssl_client) == FAIL )
		{
			ERR_print_errors_fp(stderr);
			free(ssl_client) ;
			close(client_fd);
			return ;
		}
	}

	res = ReadOneLine( buffer , sizeof(buffer) )  ;
	if(res > 0 )
	{
		if( DEBUG_MODE > 0 ) printf("[-------------------] %s[%d] : Receive --> %s", isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid(), buffer) ; 
		GetMethodUrl(buffer , REQUEST_METHOD , REQUEST_URI) ;
		if( DEBUG_MODE > 1 ) printf(  "[-------------------] %s[%d] : REQUEST_METHOD = %s ; REQUEST_URI = %s \n" , isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid(), REQUEST_METHOD , REQUEST_URI ) ;

		sprintf( logstring+strlen(logstring) , "%s %s : ", REQUEST_METHOD , REQUEST_URI ) ;
		
			
		while ( ( res = ReadOneLine( buffer , sizeof(buffer) ) ) > 0 )
		{
			if( DEBUG_MODE > 1 ) printf("[-------------------] %s[%d] : Receive --> %s",isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid(),buffer) ; 
			if( buffer[0] == 0x0a ) break ;
			
			if( ! strncasecmp(buffer,"Host:", 5) ) GetPara(buffer,HTTP_HOST, 6 ) ;
			else if( ! strncasecmp(buffer,"Connection:", 11) ) GetPara(buffer,HTTP_CONNECTION, 12 ) ;
			else if( ! strncasecmp(buffer,"Content-Length:", 15) ) GetPara(buffer,CONTENT_LENGTH, 16 ) ;
			else if( ! strncasecmp(buffer,"Cache-Control:", 14) ) GetPara(buffer,HTTP_CACHE_CONTROL, 15 ) ;
			else if( ! strncasecmp(buffer,"Accept:", 7) ) GetPara(buffer,HTTP_ACCEPT, 8 ) ;
			else if( ! strncasecmp(buffer,"Origin:", 7) ) GetPara(buffer,HTTP_ORIGIN, 8 ) ;
			else if( ! strncasecmp(buffer,"User-Agent:", 11) ) GetPara(buffer,HTTP_USER_AGENT, 12 ) ;
			else if( ! strncasecmp(buffer,"Content-Type:", 13) ) GetPara(buffer,CONTENT_TYPE, 14 ) ;
			else if( ! strncasecmp(buffer,"Referer:", 8) ) GetPara(buffer,HTTP_REFERER, 9 ) ;
			else if( ! strncasecmp(buffer,"Accept-Encoding:", 16) ) GetPara(buffer,HTTP_ACCEPT_ENCODING, 17 ) ;
			else if( ! strncasecmp(buffer,"Accept-Language:", 16) ) GetPara(buffer,HTTP_ACCEPT_LANGUAGE, 17 ) ;
			else if( ! strncasecmp(buffer,"Cookie:", 7) ) GetPara(buffer,HTTP_COOKIE, 8 ) ;
			else if( ! strncasecmp(buffer,"Range:", 6) ) GetPara(buffer,HTTP_RANGE, 7 ) ;
			else if( ! strncasecmp(buffer,"If-Range:", 9) ) GetPara(buffer,HTTP_IFRANGE, 10 ) ;
		}
		if( DEBUG_MODE > 1 ) printf( "[-------------------] %s[%d] :   HTTP_HOST =  %s , HTTP_CACHE_CONTROL =  %s , HTTP_ACCEPT_ENCODING =  %s , HTTP_USER_AGENT =  %s , HTTP_ORIGIN =  %s , HTTP_CONNECTION =  %s , HTTP_ACCEPT_LANGUAGE =  %s , HTTP_REFERER =  %s , HTTP_ACCEPT =  %s , CONTENT_LENGTH =  %s , CONTENT_TYPE =  %s ! \n",isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid() , HTTP_HOST,  HTTP_CACHE_CONTROL,  HTTP_ACCEPT_ENCODING,  HTTP_USER_AGENT,  HTTP_ORIGIN,  HTTP_CONNECTION,  HTTP_ACCEPT_LANGUAGE,  HTTP_REFERER,  HTTP_ACCEPT,  CONTENT_LENGTH,  CONTENT_TYPE  ) ;
	
		
		DelRepeatedChar(REQUEST_URI , '/') ;
		
		for( i = 0 ; REQUEST_URI[i] != '?' && REQUEST_URI[i] != '\0' ; i++ ) SCRIPT_NAME[i] = REQUEST_URI[i] ;
		SCRIPT_NAME[i] = '\0' ;
		DealPath(SCRIPT_NAME) ;
		k = 0 ;
		if( i < (int)strlen(REQUEST_URI) )
		{
			cgiFlag = 1 ;
			for( k = 0 , i++ ; REQUEST_URI[i] != '\0' ; i++ , k++ ) QUERY_STRING[k] = REQUEST_URI[i] ;
		}
		QUERY_STRING[k] = '\0' ;
		
		flag_exist = 1 ;
		sprintf(FullPath ,"%s/%s", DOCUMENT_ROOT,SCRIPT_NAME) ;
		if(stat(FullPath, &st) == -1)
		{
			flag_exist = 0 ;
			if( strlen(SCRIPT_NAME ) > 1 )
			{
				strcpy(webSite , SCRIPT_NAME+1 ) ;
				str = index(webSite , '/') ;
				if( str != NULL ) str[0] = '\0' ;
				str = QueryValue(webSite , "DOCUMENT_DIR" ) ;
				
				if( str != NULL)
				{
					strcpy(buffer , SCRIPT_NAME+1 ) ;
					nstr = index(buffer , '/');
					if( nstr != NULL && strlen(nstr)>1 ) sprintf(FullPath ,"%s/%s", str, nstr ) ;
					else sprintf(FullPath ,"%s", str ) ;
					
					nstr = QueryValue(webSite , "CGIBIN_FLAG" ) ;
					if( nstr != NULL && atoi(nstr) == 1 ) cgiFlag = 1 ;
					
					if(stat(FullPath, &st) != -1) flag_exist = 1 ;
				}
			}
		}
			
		if(flag_exist != 1)
		{
			sprintf( logstring+(strlen(logstring)) ,"SendNotFound : %s --- " , FullPath ) ;
			SendNotFound() ;
		}
		else
		{
			
			if((st.st_mode & S_IFMT) == S_IFDIR)
			{
				if( SCRIPT_NAME[strlen(SCRIPT_NAME)-1] == '/' )
				{
					sprintf( buffer , "%s/index.html" , FullPath ) ;
					if(stat(buffer, &st) == -1) 
					{
						SendDirectoryInfo(FullPath) ;
					}
					else
					{
						strcat( FullPath  , "index.html" );
						sprintf( logstring+(strlen(logstring)) , "SendHtmlContent : %s (LEN: %ld) --- " , FullPath , SendHtmlContent(FullPath) ) ;
					}
					
				}
				else
				{
					strcat( SCRIPT_NAME , "/") ;
					sprintf( logstring+(strlen(logstring)) ,"SendMovedPermanently : %s --- " , SCRIPT_NAME ) ;
					SendMovedPermanently(SCRIPT_NAME );
				}
			}
			else
			{
				alarm(SENDDATA_TIME_OUT);
				DelRepeatedChar(FullPath , '/') ;
				if( cgiFlag == 1 || ! strncasecmp(REQUEST_METHOD,"POST", 4) )
				{
					DealPath(QUERY_STRING);
					sprintf( logstring+(strlen(logstring)) , "execCgiBin : %s --- " , FullPath ) ;
					execCgiBin( FullPath , REQUEST_METHOD , QUERY_STRING ) ;
				}
				else
				{
					sprintf( logstring+(strlen(logstring)) , "SendHtmlContent : %s (LEN: %ld) --- " , FullPath , SendHtmlContent(FullPath) ) ;
					while( read( client_fd , buffer , sizeof(buffer) ) > 0 )
					{
						if( DEBUG_MODE > 0 ) printf("[-------------------] %s[%d] : Receive END --> %s",isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid(),buffer) ;
					}
				}
			}
		}
		strcat( logstring, "OK !" );
	}
	else
	{
		strcat( logstring, "NO Content !" );
	}
	WriteLogString(logstring);
	if( DEBUG_MODE > 0 ) printf( "[-------------------] %s\n",logstring) ;

	if(isHttpsProcess == 1 ) free(ssl_client) ;
	close(client_fd);
}

int StartSocketServer(int port)
{
	int sockfd;
	struct sockaddr_in addr ;
	
	if( ( sockfd = socket(AF_INET , SOCK_STREAM , 0) ) < 0 )
	{
		perror("socket");
		return -1;
	}
	bzero(&addr , sizeof(addr));
	addr.sin_family = AF_INET ;
	addr.sin_port = htons(port) ;
	addr.sin_addr.s_addr = htonl(INADDR_ANY) ;
	if( bind(sockfd , (struct sockaddr *)&addr , sizeof(addr)) < 0 )
	{
		perror("connet");
		return -1;
	}
	if( listen(sockfd , 5) < 0 )
	{
		perror("listen");
		return -1;
	}
	
	return sockfd ;
}

void HttpServer(int sockfd)
{
	struct sockaddr_in addr ;
	int addr_len = sizeof( struct sockaddr_in );
	
	signal(SIGCHLD, ChildProcessExit);

	signal(SIGALRM, ChildProcessExit);
	alarm(10);

	while(1)
	{
		client_fd = accept(sockfd ,(struct sockaddr *) &addr , (socklen_t *)&addr_len) ;

		if( client_fd < 0 )
		{
			perror("accept");
			continue ;
		}
		
		while( process_num >= MAXNUM_PROCESS )
		{
			if( DEBUG_MODE > 0 ) printf( "******* usleep *******\n") ;
			usleep(100000);
		}
		process_num++ ;
		
		//以多进程方式处理客户端
		if(fork() == 0)
		{
			close(sockfd);
			DealWithClient(client_fd);
			exit(0);
		}
		close(client_fd);
			
	}
	close(sockfd) ;
}

void PrintHelp(char * proName)
{
	printf( "\n" ) ;
	printf( "%s\n" , SERVER_VERSION) ;
	printf( "Usage: %s [ -h | -w FILEPAHT | -c FILEPAHT]\n", proName ) ;
	printf( "\t-h : Print Help\n" ) ;
	printf( "\t-w : Write Config File \n" ) ;
	printf( "\t-c : Read Config File \n" ) ;
	printf( "\n" ) ;
}

void WriteConfigFile(char * filePath)
{
	FILE * fp;
	fp=fopen(filePath,"w+");
	char* msg = "\
# configure for HttpServer v2.1\n\
\n\
[SERVER]					#SERVER CONFIG \n\
SERVER_MODE = 2					#SERVER MODE , 0: only http ; 1: only https ; >1: http and https \n\
HTTP_PORT = 8080				#HTTP SERVER LISTEN PORT\n\
HTTPS_PORT = 443				#HTTPS SERVER LISTEN PORT\n\
DOCUMENT_ROOT = /var/www/html/			#DEFAULT DOCUMENT\n\
LOG_FILE_PATH= ./HttpServer.log			#RUN LOG FILE PATH\n\
CERT_FILE_PATH = ./rsa/server.crt		#CERT FILE FOR HTTPS\n\
KEY_FILE_PATH = ./rsa/server.key		#KEY FILE FOR HTTPS\n\
MAXNUM_PROCESS = 10				#MAX CONNECT ONE TIME\n\
CONNECT_TIME_OUT = 5				#CONNECT TIME OUT , SECOND\n\
SENDDATA_TIME_OUT = 120				#SEND DATA TO CLIENT TIME OUT , SECOND\n\
DEBUG_MODE = 5					#DEBUG MODE ( 0 ~ 5 )\n\
\n\
#[hadoop]					#DOCUMENT NAME\n\
#DOCUMENT_DIR=/var/www/html/hadoop/		#DOCUMENT PATH\n\
#CGIBIN_FLAG = 0				#DOCUMENT CGI-BIN FLAG , 0: HTML  ; 1: CGI-BIN\n\
\n\n" ;
	fprintf(fp,"%s",msg);
	fclose(fp);
}

int main(int argc , char ** argv)
{
	char * str ;
	int sockfd_http , sockfd_https ;
	
	SERVER_MODE = 2 ;
	HTTP_PORT = 8080 ;
	HTTPS_PORT = 443 ;
	DEBUG_MODE = 0 ;
	CONNECT_TIME_OUT = 10 ;
	SENDDATA_TIME_OUT = 120 ;
	MAXNUM_PROCESS = 6 ;
	sprintf( DOCUMENT_ROOT , "%s" , "/var/www/html/" ) ;
	sprintf( LOG_FILE_PATH , "%s" , "./HttpServer.log" ) ;
	sprintf( CERT_FILE_PATH , "%s" , "./rsa/server.crt" ) ;
	sprintf( KEY_FILE_PATH , "%s" , "./rsa/server.key" ) ;
	
	client_fd = 0 ;
	process_num = 0 ;
	isHttpsProcess = 0 ;
	
	if( argc > 1 )
	{
		if( argc == 2 && strcmp( argv[1] , "-h") == 0 ) 
		{
			PrintHelp(argv[0]);
			return 0 ;
		}
		else if( argc == 3 && strcmp( argv[1] , "-w") == 0 )
		{
			WriteConfigFile(argv[2]) ;
			return 0 ;
		}
		else if( argc == 3 && strcmp( argv[1] , "-c") == 0 )
		{
			if( isFileExist(argv[2]) != 1 )
			{
				printf("Error: configure file not exist !\n") ;
				return 0 ;
			}
			ReadConfFile(argv[2]) ;;
		}
		else
		{
			PrintHelp(argv[0]);
			return 0 ;
		}

	} else if ( isFileExist("./HttpServer.conf") == 1 )
	{
		ReadConfFile("./HttpServer.conf") ;
	}
	
	str = QueryValue( "SERVER" , "SERVER_MODE" ) ;
	if(str != NULL ) SERVER_MODE = atoi(str) ;
	str = QueryValue( "SERVER" , "HTTP_PORT" ) ;
	if(str != NULL ) HTTP_PORT = atoi(str) ;
	str = QueryValue( "SERVER" , "HTTPS_PORT" ) ;
	if(str != NULL ) HTTPS_PORT = atoi(str) ;
	str = QueryValue( "SERVER" , "DOCUMENT_ROOT" ) ;
	if(str != NULL ) strcpy(DOCUMENT_ROOT , str);
	str = QueryValue( "SERVER" , "LOG_FILE_PATH" ) ;
	if(str != NULL ) strcpy(LOG_FILE_PATH , str);
	str = QueryValue( "SERVER" , "DEBUG_MODE" ) ;
	if(str != NULL ) DEBUG_MODE = atoi( str );
	str = QueryValue( "SERVER" , "CONNECT_TIME_OUT" ) ;
	if(str != NULL ) CONNECT_TIME_OUT = atoi( str );
	str = QueryValue( "SERVER" , "SENDDATA_TIME_OUT" ) ;
	if(str != NULL ) SENDDATA_TIME_OUT = atoi( str );
	str = QueryValue( "SERVER" , "MAXNUM_PROCESS" ) ;
	if(str != NULL ) MAXNUM_PROCESS = atoi( str );
	str = QueryValue( "SERVER" , "CERT_FILE_PATH" ) ;
	if(str != NULL ) strcpy(CERT_FILE_PATH , str);
	str = QueryValue( "SERVER" , "KEY_FILE_PATH" ) ;
	if(str != NULL ) strcpy(KEY_FILE_PATH , str);
	
	
	if( DEBUG_MODE > 0 ) 
	{
		ShowCfg() ;
		printf("================================================\n");
		printf("INFO: To start server by\n");
		printf("\t SERVER_MODE = %d \n",SERVER_MODE ) ;
		printf("\t HTTP_PORT = %d \n",HTTP_PORT ) ;
		printf("\t HTTPS_PORT = %d \n",HTTPS_PORT ) ;
		printf("\t DOCUMENT_ROOT = %s \n",DOCUMENT_ROOT ) ;
		printf("\t LOG_FILE_PATH = %s \n",LOG_FILE_PATH ) ;
		printf("\t CERT_FILE_PATH = %s \n",CERT_FILE_PATH ) ;
		printf("\t KEY_FILE_PATH = %s \n",KEY_FILE_PATH ) ;
		printf("\t MAXNUM_PROCESS = %d \n",MAXNUM_PROCESS ) ;
		printf("\t CONNECT_TIME_OUT = %d \n",CONNECT_TIME_OUT ) ;
		printf("\t SENDDATA_TIME_OUT = %d \n",SENDDATA_TIME_OUT ) ;
		printf("\t DEBUG_MODE = %d \n",DEBUG_MODE ) ;
		printf("================================================\n");
	} 
	
	//signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	if(fork() != 0)
		exit(0);

	setsid();

	if(fork() != 0)
		exit(0);
	
	if( SERVER_MODE != 1 )
	{
		sockfd_http = StartSocketServer(HTTP_PORT);
		if( sockfd_http < 0 )
		{
			printf("Error: HTTP_PORT Start Error ! StartSocketServer()\n") ;
			WriteLogString("Error: HTTP_PORT Start Error ! StartSocketServer() .") ;
			return 1;
		}
	
	}
	if( SERVER_MODE > 0 )
	{
		sockfd_https = StartSocketServer(HTTPS_PORT);
		if( sockfd_https < 0 )
		{
			printf("Error: HTTPS_PORT Start Error ! StartSocketServer()\n") ;
			WriteLogString("Error: HTTPS_PORT Start Error ! StartSocketServer() .") ;
			return 1;
		}
		
		SSL_library_init();
		ctx = InitServerCTX();/* initialize SSL */
		LoadCertificates(ctx, CERT_FILE_PATH, KEY_FILE_PATH);  /* load certs */
	
	}

	if( SERVER_MODE == 0 )
	{
		HttpServer(sockfd_http) ;
	}
	else if( SERVER_MODE == 1 )
	{
		isHttpsProcess = 1 ;
		HttpServer(sockfd_https) ;
	}
	else
	{
		if(fork() == 0 )
		{
			isHttpsProcess = 1 ;
			close(sockfd_http) ;
			sprintf(logstring,"HTTPS Sever start by Port:%d success !",HTTPS_PORT  );
			if( DEBUG_MODE > 0 ) printf("[-------------------] %s[%d] : %s\n",isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid(),logstring) ;
			WriteLogString(logstring);
			HttpServer(sockfd_https) ;
		}
		else
		{
			isHttpsProcess = 0 ;
			close(sockfd_https)  ;
			sprintf(logstring,"HTTP Sever start by Port:%d success !",HTTP_PORT  );
			if( DEBUG_MODE > 0 ) printf("[-------------------] %s[%d] : %s\n",isHttpsProcess == 1 ? "HTTPS" : "HTTP" , getpid(),logstring) ;
			WriteLogString(logstring);
			HttpServer(sockfd_http) ;
		}
	}
	
	
	return 0 ;
}


