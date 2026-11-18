CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11
SRC      = src/server.c src/hp.c
HDR      = src/common.h src/hp.h
NSLOT   ?= 4
EXP_SLOTS = 4 64 1024

.PHONY: all test test-extra exp-build exp clean

all: bin/vuln bin/patch bin/honey bin/honey-noredact

bin:
	mkdir -p bin logs experiments/results

bin/vuln: $(SRC) $(HDR) | bin
	$(CC) $(CFLAGS) -DNSLOT=$(NSLOT) -DVARIANT=\"vuln\" -o $@ $(SRC)

bin/patch: $(SRC) $(HDR) | bin
	$(CC) $(CFLAGS) -DNSLOT=$(NSLOT) -DVARIANT=\"patch\" -DPATCH -o $@ $(SRC)

bin/honey: $(SRC) $(HDR) | bin
	$(CC) $(CFLAGS) -DNSLOT=$(NSLOT) -DVARIANT=\"honey\" -DHONEY -o $@ $(SRC)

bin/honey-noredact: $(SRC) $(HDR) | bin
	$(CC) $(CFLAGS) -DNSLOT=$(NSLOT) -DVARIANT=\"honey-noredact\" -DHONEY -DNO_REDACT -o $@ $(SRC)

# 11주차 고정 검증 사례 실행 (README의 한 줄 실행)
test: all
	python3 tests/run_cases.py tests/cases_fixed.csv

# 13주차 추가 사례
test-extra: all
	python3 tests/run_cases.py tests/cases_extra.csv

# 실험용: 세션 슬롯 수별 바이너리
exp-build: | bin
	for n in $(EXP_SLOTS); do \
	  $(CC) $(CFLAGS) -DNSLOT=$$n -DVARIANT=\"honey\" -DHONEY -o bin/honey_n$$n $(SRC); \
	  $(CC) $(CFLAGS) -DNSLOT=$$n -DVARIANT=\"honey-noredact\" -DHONEY -DNO_REDACT -o bin/honey-noredact_n$$n $(SRC); \
	done

exp: all exp-build
	python3 experiments/exp_redaction.py

clean:
	rm -rf bin logs/*.log
