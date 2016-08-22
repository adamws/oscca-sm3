OBJECTS = sm3.o ./core/sm3_internal.o
INCLUDES = -I. -I./core
CFLAGS = -g -Wall -O3
CC = c99

OUT = libsm3.a

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES)

$(OUT): $(OBJECTS)
	ar rcs $(OUT) $(OBJECTS)
