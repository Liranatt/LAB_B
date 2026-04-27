CC=gcc
CFLAGS=-Wall -Wextra -g -std=c11
TARGET=bubblesort

all: $(TARGET)

$(TARGET): lab3_bubblesort.c
	$(CC) $(CFLAGS) -o $(TARGET) lab3_bubblesort.c

clean:
	rm -f $(TARGET)