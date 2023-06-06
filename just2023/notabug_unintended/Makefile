# Define compiler
CC = gcc
# Define compiler flags
CFLAGS = -fPIC -Wall -Wextra
# Define linker flags
LDFLAGS = -shared
# Define output library name
LIBNAME = lib.so
# Define source files
SRCS = test.c

all:
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(LIBNAME) $(SRCS)

clean:
	rm -f $(LIBNAME)


