CC	   = g++
CFLAGS = -g -Wall
OBJS   = main.o
TARGET = tcp_data_change

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) -lnetfilter_queue
	rm *.o

main.o: header.h function.h main.cpp

clean:
	rm -rf *.o $(TARGET)
