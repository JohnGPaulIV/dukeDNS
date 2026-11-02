#
# Simple Makefile
# Mike Lam, James Madison University, August 2016
#
# This makefile builds a simple application that contains a main module
# (specified by the EXE variable) and a predefined list of additional modules
# (specified by the MODS variable). If there are any external library
# dependencies (e.g., the math library, "-lm"), list them in the LIBS variable.
# If there are any precompiled object files, list them in the OBJS variable.
#
# By default, this makefile will build the project with debugging symbols and
# without optimization. To change this, edit or remove the "-g" and "-O0"
# options in CFLAGS and LDFLAGS accordingly.
#
# By default, this makefile build the application using the GNU C compiler,
# adhering to the C99 standard with all warnings enabled.


# application-specific settings and run target

EXEC=digduke
EXES=dukens
MODC=client.o dns.o utils.o
MODS=server.o dns.o utils.o
OBJS=port_utils.o
LIBS=-lm

default: build $(EXEC) $(EXES)

build:
	@mkdir build

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
else ifeq (status,$(firstword $(MAKECMDGOALS)))
  # use the rest as arguments for "status"
  RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(RUN_ARGS):;@:)
endif

test: build $(EXE)
	@make -C tests test $(RUN_ARGS)

utest: build $(EXE)
	@make -C tests utest

check: build $(EXE)
	@make -C tests check "$(RUN_ARGS)"

submit: build $(EXE)
	@make -C tests submit "$(RUN_ARGS)"

status: build $(EXE)
	@make -C tests status

style: $(EXE)
	@make -C tests style

# compiler/linker settings

CC=gcc
CFLAGS=-g -O0 -Wall -Werror --std=gnu99 -pedantic
LDFLAGS=-g -O0 -pthread


# build targets

BUILDC=$(addprefix build/, $(MODC))

BUILDS=$(addprefix build/, $(MODS))

$(EXEC): $(BUILDC) $(OBJS)
	$(CC) $(LDFLAGS) -o $(EXEC) $^ $(LIBS)

$(EXES): $(BUILDS) $(OBJS)
	$(CC) $(LDFLAGS) -o $(EXES) $^ $(LIBS)

build/%.o: src/%.c
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	rm -rf $(EXEC) $(EXES) build
	make -C tests clean

.PHONY: default clean test check style submit status

