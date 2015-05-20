all : HttpServer

HttpServer.o : HttpServer.c HttpServer.h
	gcc -g -W -Wall -c HttpServer.c -o HttpServer.o

ReadConfFile.o : ReadConfFile.c ReadConfFile.h
	gcc -g -W -Wall -c ReadConfFile.c -o ReadConfFile.o

HttpServer : ReadConfFile.o HttpServer.o
	gcc -g -W -Wall -o HttpServer HttpServer.o ReadConfFile.o -lpthread



.PHONY:clean
clean :
	rm -f HttpServer *.o
rebuild : clean all
