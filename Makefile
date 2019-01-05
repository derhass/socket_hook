CPPFLAGS += -Wall -Wextra

ifeq ($(DEBUG), 1)
CFLAGS += -g
CPPFLAGS += -Werror
else
CFLAGS += -O2
CPPFLAGS += -DNDEBUG
endif

STDDEFINES=
BAREDEFINES=

.PHONY: all
all: socket_hook.so

socket_hook.so: socket_hook.c Makefile
	$(CC)  -shared -fPIC -Bsymbolic -pthread -o $@ $< $(CPPFLAGS) $(STDDEFINES) $(CFLAGS) $(LDFLAGS) -lrt

.PHONY: clean
clean: 
	-rm socket_hook.so

