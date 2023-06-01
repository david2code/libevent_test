TARGET := libevent_main
CC := gcc
LIBS := -levent


SOURCE := $(wildcard *.c)
OBJS := $(patsubst %.c,%.o,$(SOURCE))

.PHONY : all clean

all : $(TARGET)

${TARGET} : $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

clean:
	rm -rf *.o ${TARGET}
