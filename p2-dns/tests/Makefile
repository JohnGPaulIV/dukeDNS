#
# Simple Test Makefile
# Mike Lam, James Madison University, August 2016
#
# This version of the Makefile includes support for building a test suite. The
# recommended framework is Check (http://check.sourceforge.net/). To build and
# run the test suite, execute the "test" target. The test suite must be located
# in a module called "testsuite". The MODS, LIBS, and OBJS variables work as
# they do in the main Makefile.
#
# To change the default build target (which executes when you just type
# "make"), change the right-hand side of the definition of the "default"
# target.
#
# By default, this makefile will build the project with debugging symbols and
# without optimization. To change this, edit or remove the "-g" and "-O0"
# options in CFLAGS and LDFLAGS accordingly.
#
# By default, this makefile build the application using the GNU C compiler,
# adhering to the C99 standard with all warnings enabled.


# application-specific settings and run target

EXE=../digduke
TEST=testsuite
MODS=public.o
OBJS=../port_utils.o
LIBS=

TESTOUT=tests.txt
UTESTOUT=utests.txt
ITESTOUT=itests.txt
SCHECKOUT=style.txt

default: $(TEST)


$(EXE):
	make -C ../

ifeq (test,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "test"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
else ifeq (check,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "check"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
else ifeq (submit,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "submit"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif

#test: itest style
#	@echo "========================================"

utest: $(EXE) $(TEST)
	@echo "========================================"
	@echo "             UNIT TESTS"
	@./$(TEST) 2>/dev/null >$(UTESTOUT)
	@cat $(UTESTOUT) | sed -n -e '/Checks/,$$p' | sed -e 's/^private.*:[EF]://g'

test: $(EXE)
	@echo "========================================"
	@echo "            INTEGRATION TESTS"
	@./integration.sh "$(RUN_ARGS)" | tee $(ITESTOUT)

check: $(EXE)
	@echo "========================================"
	@echo "            CHECKING FEATURE"
	@./grade.sh.local "$(RUN_ARGS)" | tee $(TESTOUT)

submit: $(EXE) style
	@echo "========================================"
	@echo "           GRADING SUBMISSION"
	@./grade.sh "$(RUN_ARGS)" | tee $(TESTOUT)

status: $(EXE)
	@echo "========================================"
	@echo "          CHECKING GRADE STATUS"
	@echo "----------------------------------------"
	@./grade.sh status | tee $(TESTOUT)

style: $(EXE)
	@echo "========================================"
	@echo "          CODING STYLE CHECK"
	@./style.sh 2>/dev/null | tee $(SCHECKOUT)
	@grep "Code correctly adheres to required style." $(SCHECKOUT) >/dev/null 2>&1

# compiler/linker settings

CC=gcc
CFLAGS=-g -O0 -Wall --std=gnu99 -pedantic
LDFLAGS=-g -O0

# macOS version:
#CFLAGS+=-I/opt/homebrew/Cellar/check/0.15.2/include -Wno-gnu-zero-variadic-macro-arguments
#LDFLAGS+=-L/opt/homebrew/Cellar/check/0.15.2
# Linux version:
#CFLAGS+=-Wno-gnu-zero-variadic-macro-arguments
#LDFLAGS+=
LIBS+=-lcheck -lm -lpthread
CFLAGS=
LIBS+=-lcheck -lm -lpthread

ifeq ($(shell uname -s),Linux)
	LIBS+=-lrt -lsubunit
endif


# build targets

$(TEST): $(TEST).o $(MODS) $(OBJS)
	$(CC) $(LDFLAGS) -o $(TEST) $^ $(LIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) $<

clean:
	rm -rf $(TEST) $(TEST).o $(MODS) $(TESTOUT) $(UTESTOUT) $(ITESTOUT) $(SCHECKOUT) outputs valgrind ckstyle

.PHONY: default clean check test style status submit

