# ======================================================================
# Useful for feedback

CC = clang

TARGETS := utils stats

EXECS=$(foreach name,$(TARGETS),unit-test-$(name))

.PHONY: unit-tests all $(TARGETS) execs

# first creates all exec, **then** launch them
all: execs unit-tests
	echo $(EXECS)

unit-tests: $(TARGETS)

execs: $(EXECS)

# some target shortcuts : compile & run the tests
utils: unit-test-utils
	./unit-test-utils
stats: unit-test-stats
	./unit-test-stats

# ======================================================================
SRC_DIR:=../../done
CFLAGS  += -I$(SRC_DIR) -DCS212_TEST
LDFLAGS += -L$(SRC_DIR)
LDLIBS  += -lm -lssl -lcrypto -lcurl -ljson-c

CFLAGS  += -fsanitize=address
LDFLAGS += -fsanitize=address
LDLIBS  += -fsanitize=address

ckvs_test_util.o: ckvs_test_util.c

unit-test-utils.o: unit-test-utils.c
unit-test-utils: LDLIBS += -lcheck -lm -lrt -pthread -lsubunit
unit-test-utils: unit-test-utils.o ckvs_test_util.o \
   $(SRC_DIR)/error.o $(SRC_DIR)/ckvs_utils.o

unit-test-stats.o: unit-test-stats.c
unit-test-stats: LDLIBS += -lcheck -lm -lrt -pthread -lsubunit
unit-test-stats: unit-test-stats.o ckvs_test_util.o \
   $(SRC_DIR)/error.o $(SRC_DIR)/ckvs_utils.o $(SRC_DIR)/ckvs_local.o

# ======================================================================
.PHONY: clean dist-clean reset

clean::
	-$(RM) *.o *~

dist-clean: clean
	-$(RM) $(foreach T,$(TARGETS),unit-test-$(T))

reset: dist-clean all
