MKDIR = mkdir -p

CC = c99
CLFAGS = -g -Wall -O3

ODIR = obj
LDIR = -L../sm3 
LIBS = -lsm3 -largp

_OBJ = example.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c
	$(MKDIR) $(ODIR)
	$(CC) -c -o $@ $< $(CFLAGS)

example: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LDIR) $(LIBS)

.PHONY clean:

clean:
	rm -f $(ODIR)/*.o
