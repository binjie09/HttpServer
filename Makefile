all : HttpServer

HttpServer.o : HttpServer.c HttpServer.h
	gcc -g -W -Wall -c HttpServer.c -o HttpServer.o

ReadConfFile.o : ReadConfFile.c ReadConfFile.h
	gcc -g -W -Wall -c ReadConfFile.c -o ReadConfFile.o
	
MD5: MD5.c MD5.h
	gcc -g -W -Wall -c MD5.c -o MD5.o

HttpServer : ReadConfFile.o MD5.o HttpServer.o 
	gcc -g -W -Wall -o HttpServer HttpServer.o ReadConfFile.o MD5.o -lpthread



.PHONY:clean
clean :
	rm -f HttpServer *.o
rebuild : clean all
