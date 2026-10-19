CXX := clang++ -fuse-ld=lld
CPPFLAGS ?=
LDLIBS := -lsodium -lcrypto

COMMON_WARN := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wformat=2
COMMON_HARDEN := -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -fstack-protector-strong -fstack-clash-protection -fPIE
COMMON_LINK_HARDEN := -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack,-z,defs
COMMON := -std=c++23 -fno-rtti $(COMMON_WARN) $(COMMON_HARDEN)

.PHONY: all release native debug sanitize full-suite check check-compat check-sanitize clean

all: release

release: symfrog512

symfrog512: src/symfrog512.cpp
	$(CXX) $(CPPFLAGS) $(COMMON) -O3 -flto $< -o $@ -flto $(COMMON_LINK_HARDEN) $(LDLIBS)

native: src/symfrog512.cpp
	$(CXX) $(CPPFLAGS) $(COMMON) -O3 -march=native -mtune=native -flto $< -o symfrog512-native -flto $(COMMON_LINK_HARDEN) $(LDLIBS)

debug: src/symfrog512.cpp
	$(CXX) $(CPPFLAGS) $(COMMON) -O0 -g3 -fno-omit-frame-pointer $< -o symfrog512-debug $(COMMON_LINK_HARDEN) $(LDLIBS)

sanitize: src/symfrog512.cpp
	$(CXX) $(CPPFLAGS) -std=c++23 -fno-rtti $(COMMON_WARN) -D_FILE_OFFSET_BITS=64 -D_GLIBCXX_ASSERTIONS -O1 -g3 -fno-omit-frame-pointer \
		-fsanitize=address,undefined -fno-sanitize-recover=all $< -o symfrog512-sanitize $(LDLIBS)

full-suite: src/symfrog_full_suite.cpp src/symfrog512.cpp
	$(CXX) $(CPPFLAGS) $(COMMON) -O2 -g $< -o symfrog_full_suite $(COMMON_LINK_HARDEN) $(LDLIBS)

check: release
	./symfrog512 --test-all
	python3 tests/test_v3_compatibility.py
	python3 tests/test_v4_init.py
	python3 tests/test_v5_siv.py
	python3 tests/test_io_regressions.py

check-compat: release
	python3 tests/test_v3_compatibility.py

check-sanitize: sanitize
	ASAN_OPTIONS=detect_leaks=1 ./symfrog512-sanitize --test-all

clean:
	rm -f symfrog512 symfrog512-native symfrog512-debug symfrog512-sanitize symfrog_full_suite
