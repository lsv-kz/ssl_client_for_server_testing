CFLAGS = -Wall -std=c++11 
CC = c++
#CC = clang++ 	

OBJSDIR = objs
#$(shell mkdir -p $(OBJSDIR))

DEPS = client.h

OBJS = $(OBJSDIR)/client.o \
	$(OBJSDIR)/ssl.o \
	$(OBJSDIR)/child_proc.o \
	$(OBJSDIR)/first_request.o \
	$(OBJSDIR)/request.o \
	$(OBJSDIR)/request_trigger.o \
	$(OBJSDIR)/create_client_socket.o \
	$(OBJSDIR)/rd_wr.o \
	$(OBJSDIR)/functions.o 

client: $(OBJS) 
	$(CC) $(CFLAGS) -o $@ $(OBJS)  -lpthread -L/usr/local/lib/ -L/usr/local/lib64/ -lssl -lcrypto

$(OBJSDIR)/client.o: client.cpp client.h
	$(CC) $(CFLAGS) -c client.cpp -o $@

$(OBJSDIR)/ssl.o: ssl.cpp client.h
	$(CC) $(CFLAGS) -c ssl.cpp -o $@

$(OBJSDIR)/child_proc.o: child_proc.cpp client.h
	$(CC) $(CFLAGS) -c child_proc.cpp -o $@

$(OBJSDIR)/request.o: request.cpp client.h
	$(CC) $(CFLAGS) -c request.cpp -o $@

$(OBJSDIR)/first_request.o: first_request.cpp client.h
	$(CC) $(CFLAGS) -c first_request.cpp -o $@

$(OBJSDIR)/request_trigger.o: request_trigger.cpp client.h
	$(CC) $(CFLAGS) -c request_trigger.cpp -o $@

$(OBJSDIR)/create_client_socket.o: create_client_socket.cpp client.h
	$(CC) $(CFLAGS) -c create_client_socket.cpp -o $@

$(OBJSDIR)/rd_wr.o: rd_wr.cpp client.h
	$(CC) $(CFLAGS) -c rd_wr.cpp -o $@

$(OBJSDIR)/functions.o: functions.cpp client.h
	$(CC) $(CFLAGS) -c functions.cpp -o $@

clean:
	rm -f client
	rm -f $(OBJSDIR)/*.o
