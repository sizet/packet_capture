# ©.

CROSS        =
export CC    = $(CROSS)gcc
export LD    = $(CROSS)ld
export AR    = $(CROSS)ar
export STRIP = $(CROSS)strip

CC_FLAGS = -Wall -O2
LD_FLAGS =

INCLUDE_PATH =
LIBRARY_PATH =

LIBRARY_FILE =

SOURCE_FILE = $(wildcard *.c)
OBJECT_FILE = $(SOURCE_FILE:.c=.o)
TARGET_FILE = packet_capture


all : $(TARGET_FILE)


$(TARGET_FILE) : $(OBJECT_FILE)
	$(CC) $(LD_FLAGS) $(LIBRARY_PATH) $^ $(LIBRARY_FILE) -o $@
	$(STRIP) $@

%.o : %.c
	$(CC) $(CC_FLAGS) $(INCLUDE_PATH) -c $< -o $@

%.d : %.c
	@set -e; rm -f $@; \
	$(CC) $(CC_FLAGS) $(INCLUDE_PATH) -MM $< > $@.$$$$; 2>/dev/null; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(SOURCE_FILE:.c=.d)

clean :
	rm -f *.d *.d* *.o $(TARGET_FILE)
