# Userspace verification harness for the read-only sfs driver.
# Builds sfs_verify from the SAME format/crypto .c files the kernel module uses
# (minus VFS), plus the OpenSSL backend. A green run proves the on-disk format
# is understood byte-exactly before any kernel code exists.
#
#   make            # build sfs_verify
#   make verify     # regenerate golden fixtures + run
#
# OpenSSL discovery: honour a brew prefix on macOS, fall back to system paths.

OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null)
ifneq ($(OPENSSL_PREFIX),)
  SSL_CFLAGS := -I$(OPENSSL_PREFIX)/include
  SSL_LDFLAGS := -L$(OPENSSL_PREFIX)/lib
endif

CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -std=gnu11 $(SSL_CFLAGS)
LDFLAGS ?= $(SSL_LDFLAGS) -lcrypto

KDIR := ..
SRCS := \
  $(KDIR)/sfs_util.c \
  $(KDIR)/sfs_crypto.c \
  $(KDIR)/sfs_header.c \
  $(KDIR)/sfs_trie.c \
  $(KDIR)/sfs_record.c \
  $(KDIR)/sfs_sign.c \
  $(KDIR)/sfs_ed25519.c \
  $(KDIR)/sfs_attr.c \
  $(KDIR)/sfs_encode.c \
  $(KDIR)/sfs_tail.c \
  $(KDIR)/sfs_cow.c \
  $(KDIR)/sfs_meta.c \
  $(KDIR)/sfs_wal.c \
  sfs_backend_openssl.c \
  sfs_verify.c

REPO := $(KDIR)/..
GOLDEN := /tmp/sfs-golden

# Write-path harness: builds sfs_mkfs from the ENCODE + CRYPTO core (+ shared
# CRC) and the OpenSSL backend. Crypto is needed for --cipher xts/gcm (content
# seal + GCM record/trie seal); cipher=none still works without touching it.
MKFS_SRCS := \
  $(KDIR)/sfs_util.c \
  $(KDIR)/sfs_crypto.c \
  $(KDIR)/sfs_encode.c \
  $(KDIR)/sfs_catalog.c \
  sfs_backend_openssl.c \
  sfs_mkfs.c

sfs_verify: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

sfs_mkfs: $(MKFS_SRCS)
	$(CC) $(CFLAGS) -o $@ $(MKFS_SRCS) $(LDFLAGS)

# Adversarial-container crafter (writes poisoned NONE images) + userspace probe
# that drives the SAME reader code the kernel uses (trie walk/scan/lookup +
# record parse) so hardening can be checked before touching the VM.
EVIL_SRCS := \
  $(KDIR)/sfs_util.c \
  $(KDIR)/sfs_crypto.c \
  $(KDIR)/sfs_encode.c \
  $(KDIR)/sfs_catalog.c \
  sfs_backend_openssl.c \
  sfs_evil.c
PROBE_SRCS := \
  $(KDIR)/sfs_util.c \
  $(KDIR)/sfs_crypto.c \
  $(KDIR)/sfs_header.c \
  $(KDIR)/sfs_trie.c \
  $(KDIR)/sfs_record.c \
  $(KDIR)/sfs_sign.c \
  $(KDIR)/sfs_ed25519.c \
  sfs_backend_openssl.c \
  sfs_probe.c

sfs_evil: $(EVIL_SRCS)
	$(CC) $(CFLAGS) -o $@ $(EVIL_SRCS) $(LDFLAGS)

sfs_probe: $(PROBE_SRCS)
	$(CC) $(CFLAGS) -o $@ $(PROBE_SRCS) $(LDFLAGS)

# Byte-preserving header-commit regression (WS1 1.1): drives the SAME
# sfs_enc_header_commit the kernel commit uses against a golden container.
COMMITTEST_SRCS := \
  $(KDIR)/sfs_util.c \
  $(KDIR)/sfs_crypto.c \
  $(KDIR)/sfs_header.c \
  $(KDIR)/sfs_encode.c \
  sfs_backend_openssl.c \
  sfs_committest.c

sfs_committest: $(COMMITTEST_SRCS)
	$(CC) $(CFLAGS) -o $@ $(COMMITTEST_SRCS) $(LDFLAGS)

# Eviction-tail allocator regression (WS1 1.3): frontier walk + tail scan via
# the SAME sfs_tail.c the kernel compiles, checked against the Rust engine's
# reopen-derived anchors in golden-history.manifest.
ALLOCTEST_SRCS := \
  $(KDIR)/sfs_util.c \
  $(KDIR)/sfs_crypto.c \
  $(KDIR)/sfs_header.c \
  $(KDIR)/sfs_trie.c \
  $(KDIR)/sfs_record.c \
  $(KDIR)/sfs_sign.c \
  $(KDIR)/sfs_ed25519.c \
  $(KDIR)/sfs_tail.c \
  $(KDIR)/sfs_encode.c \
  sfs_backend_openssl.c \
  sfs_alloctest.c

sfs_alloctest: $(ALLOCTEST_SRCS)
	$(CC) $(CFLAGS) -o $@ $(ALLOCTEST_SRCS) $(LDFLAGS)

# Dynamic-record-buffer regression (WS1 1.6): builds a >5 MiB-record container
# (300k hole fragments) and re-reads it through the shared parsers.
BIGREC_SRCS := \
  $(KDIR)/sfs_util.c \
  $(KDIR)/sfs_crypto.c \
  $(KDIR)/sfs_header.c \
  $(KDIR)/sfs_trie.c \
  $(KDIR)/sfs_record.c \
  $(KDIR)/sfs_sign.c \
  $(KDIR)/sfs_ed25519.c \
  $(KDIR)/sfs_encode.c \
  $(KDIR)/sfs_catalog.c \
  sfs_backend_openssl.c \
  sfs_bigrec.c

sfs_bigrec: $(BIGREC_SRCS)
	$(CC) $(CFLAGS) -o $@ $(BIGREC_SRCS) $(LDFLAGS)

# WS3 CoW mutation harness: the SAME portable commit machinery the kernel
# compiles (sfs_cow.c) mutates Rust-written goldens; the Rust engine then
# re-verifies (fsck + head content + MVCC history resolve) via sfs_cowcheck.sh.
COWTEST_SRCS := \
  $(KDIR)/sfs_util.c \
  $(KDIR)/sfs_crypto.c \
  $(KDIR)/sfs_header.c \
  $(KDIR)/sfs_trie.c \
  $(KDIR)/sfs_record.c \
  $(KDIR)/sfs_sign.c \
  $(KDIR)/sfs_ed25519.c \
  $(KDIR)/sfs_attr.c \
  $(KDIR)/sfs_meta.c \
  $(KDIR)/sfs_ns.c \
  $(KDIR)/sfs_tail.c \
  $(KDIR)/sfs_encode.c \
  $(KDIR)/sfs_catcow.c \
  $(KDIR)/sfs_cow.c \
  sfs_backend_openssl.c \
  sfs_cowtest.c

sfs_cowtest: $(COWTEST_SRCS)
	$(CC) $(CFLAGS) -o $@ $(COWTEST_SRCS) $(LDFLAGS)

# WS8 harness: path-CoW catalogs (sfs_catcow.c) + freelist allocator
# (sfs_falloc.c) — O(depth) node writes, bounded growth under commit churn,
# committed-node crash-safety instrumentation; Rust re-verifies via cowcheck.
TRIECOW_SRCS := \
  $(KDIR)/sfs_util.c \
  $(KDIR)/sfs_crypto.c \
  $(KDIR)/sfs_header.c \
  $(KDIR)/sfs_trie.c \
  $(KDIR)/sfs_record.c \
  $(KDIR)/sfs_sign.c \
  $(KDIR)/sfs_ed25519.c \
  $(KDIR)/sfs_attr.c \
  $(KDIR)/sfs_meta.c \
  $(KDIR)/sfs_tail.c \
  $(KDIR)/sfs_encode.c \
  $(KDIR)/sfs_catcow.c \
  $(KDIR)/sfs_falloc.c \
  $(KDIR)/sfs_cow.c \
  sfs_backend_openssl.c \
  sfs_triecow.c

sfs_triecow: $(TRIECOW_SRCS)
	$(CC) $(CFLAGS) -o $@ $(TRIECOW_SRCS) $(LDFLAGS)

# WS11 11.1 harness: eviction bands/pins through the SAME portable core the
# kernel compiles (sfs_evict.c), decision-diffed against the Rust reference
# (sfs-evict) and re-verified via cowcheck.
EVICTTEST_SRCS := \
  $(KDIR)/sfs_util.c \
  $(KDIR)/sfs_crypto.c \
  $(KDIR)/sfs_header.c \
  $(KDIR)/sfs_trie.c \
  $(KDIR)/sfs_record.c \
  $(KDIR)/sfs_sign.c \
  $(KDIR)/sfs_ed25519.c \
  $(KDIR)/sfs_attr.c \
  $(KDIR)/sfs_meta.c \
  $(KDIR)/sfs_tail.c \
  $(KDIR)/sfs_encode.c \
  $(KDIR)/sfs_catcow.c \
  $(KDIR)/sfs_falloc.c \
  $(KDIR)/sfs_cow.c \
  $(KDIR)/sfs_evict.c \
  sfs_backend_openssl.c \
  sfs_evicttest.c

sfs_evicttest: $(EVICTTEST_SRCS)
	$(CC) $(CFLAGS) -o $@ $(EVICTTEST_SRCS) $(LDFLAGS)

# WS11 11.2 harness: defrag through the SAME portable core the kernel
# compiles (sfs_defrag.c), fixpoint-converged, Rust re-verified via cowcheck.
DEFRAGTEST_SRCS := \
  $(KDIR)/sfs_util.c \
  $(KDIR)/sfs_crypto.c \
  $(KDIR)/sfs_header.c \
  $(KDIR)/sfs_trie.c \
  $(KDIR)/sfs_record.c \
  $(KDIR)/sfs_sign.c \
  $(KDIR)/sfs_ed25519.c \
  $(KDIR)/sfs_attr.c \
  $(KDIR)/sfs_meta.c \
  $(KDIR)/sfs_tail.c \
  $(KDIR)/sfs_encode.c \
  $(KDIR)/sfs_catcow.c \
  $(KDIR)/sfs_falloc.c \
  $(KDIR)/sfs_cow.c \
  $(KDIR)/sfs_defrag.c \
  sfs_backend_openssl.c \
  sfs_defragtest.c

sfs_defragtest: $(DEFRAGTEST_SRCS)
	$(CC) $(CFLAGS) -o $@ $(DEFRAGTEST_SRCS) $(LDFLAGS)

# WS11 11.3 discard-rule unit test (fake discard callback; both-slots rule).
sfs_trimtest: $(KDIR)/sfs_util.c $(KDIR)/sfs_falloc.c sfs_trimtest.c
	$(CC) $(CFLAGS) -o $@ $(KDIR)/sfs_util.c $(KDIR)/sfs_falloc.c sfs_trimtest.c

# WS11 maintenance CLI (evict/defrag/trim ioctls). Linux-only at runtime;
# builds everywhere (non-Linux main is a stub).
sfsctl: sfsctl.c $(KDIR)/sfs_ioctl.h
	$(CC) $(CFLAGS) -o $@ sfsctl.c

# WS10 Ed25519 known-answer gate: RFC 8032 §7.1 vectors + negatives + dalek
# cross-vectors (ed25519-vectors.txt) through the SAME ref10 core the kernel
# compiles (sfs_ed25519.c). MUST pass before any signed-container work.
EDTEST_SRCS := \
  $(KDIR)/sfs_ed25519.c \
  sfs_backend_openssl.c \
  sfs_edtest.c

sfs_edtest: $(EDTEST_SRCS) $(KDIR)/sfs_ed25519.h $(KDIR)/sfs_ed25519_tables.h
	$(CC) $(CFLAGS) -o $@ $(EDTEST_SRCS) $(LDFLAGS)

# D3 harness: v3 ATTR xattr codec (parse/get/list/re-encode) proven against
# the attr.rs KAT vectors (xattr-vectors.txt) — byte-parity Kernel↔Rust.
XATTRTEST_SRCS := \
  $(KDIR)/sfs_util.c \
  $(KDIR)/sfs_attr.c \
  sfs_xattrtest.c

sfs_xattrtest: $(XATTRTEST_SRCS)
	$(CC) $(CFLAGS) -o $@ $(XATTRTEST_SRCS) $(LDFLAGS)

# WS9 harness: WAL replay (9.1) + checkpoint fold (9.2) against golden-wal,
# through the SAME portable code the kernel compiles; Rust re-verifies.
WALTEST_SRCS := \
  $(KDIR)/sfs_util.c \
  $(KDIR)/sfs_crypto.c \
  $(KDIR)/sfs_header.c \
  $(KDIR)/sfs_trie.c \
  $(KDIR)/sfs_record.c \
  $(KDIR)/sfs_sign.c \
  $(KDIR)/sfs_ed25519.c \
  $(KDIR)/sfs_attr.c \
  $(KDIR)/sfs_meta.c \
  $(KDIR)/sfs_tail.c \
  $(KDIR)/sfs_encode.c \
  $(KDIR)/sfs_catcow.c \
  $(KDIR)/sfs_falloc.c \
  $(KDIR)/sfs_cow.c \
  $(KDIR)/sfs_wal.c \
  sfs_backend_openssl.c \
  sfs_waltest.c

sfs_waltest: $(WALTEST_SRCS)
	$(CC) $(CFLAGS) -o $@ $(WALTEST_SRCS) $(LDFLAGS)

# WS6 6.1/6.2/6.4: the shared portable mutation engine (sfs_mut.c) drives the
# SAME core the kernel compiles. sfs_mut = scripted CLI; sfs_fuzz = seeded
# differential fuzzer over the identical engine (compiled with -DSFS_MUT_NO_MAIN
# so it supplies its own main).
MUT_CORE := \
  $(KDIR)/sfs_util.c \
  $(KDIR)/sfs_crypto.c \
  $(KDIR)/sfs_header.c \
  $(KDIR)/sfs_trie.c \
  $(KDIR)/sfs_record.c \
  $(KDIR)/sfs_sign.c \
  $(KDIR)/sfs_ed25519.c \
  $(KDIR)/sfs_attr.c \
  $(KDIR)/sfs_meta.c \
  $(KDIR)/sfs_ns.c \
  $(KDIR)/sfs_tail.c \
  $(KDIR)/sfs_encode.c \
  $(KDIR)/sfs_catcow.c \
  $(KDIR)/sfs_falloc.c \
  $(KDIR)/sfs_cow.c \
  $(KDIR)/sfs_evict.c \
  $(KDIR)/sfs_defrag.c \
  sfs_backend_openssl.c

sfs_mut: $(MUT_CORE) sfs_mut.c sfs_mut.h
	$(CC) $(CFLAGS) -o $@ $(MUT_CORE) sfs_mut.c $(LDFLAGS)

sfs_fuzz: $(MUT_CORE) sfs_mut.c sfs_mut.h sfs_fuzz.c
	$(CC) $(CFLAGS) -DSFS_MUT_NO_MAIN -o $@ $(MUT_CORE) sfs_mut.c sfs_fuzz.c $(LDFLAGS)

.PHONY: verify roundtrip fuzz fuzz-soak golden clean
golden:
	# build ALL tools bins (not a hand-maintained subset): the verify harness
	# also shells out to sfs-evict (evicttest E2 parity) and others, and a
	# missing bin only surfaces on a clean checkout as a 127 mid-run.
	cd $(REPO) && cargo build -p zero-sfs-tools --release
	$(REPO)/target/release/sfs-mkgolden $(GOLDEN)

verify: sfs_verify sfs_committest sfs_alloctest sfs_bigrec sfs_cowtest sfs_triecow sfs_waltest sfs_evicttest sfs_defragtest sfs_trimtest sfs_edtest sfs_xattrtest sfsctl golden
	@echo "- edtest (WS10: RFC 8032 + dalek cross-vectors, negatives)"
	./sfs_edtest $(GOLDEN)
	@echo "- xattrtest (D3: v3 ATTR xattr codec, attr.rs KAT byte-parity)"
	./sfs_xattrtest $(GOLDEN)
	./sfs_verify $(GOLDEN)
	@echo "- committest (byte-preserving header commit)"
	cp $(GOLDEN)/golden-gcm.sfs $(GOLDEN)/committest.sfs
	./sfs_committest $(GOLDEN)/committest.sfs
	@echo "- alloctest (eviction-tail allocator)"
	cp $(GOLDEN)/golden-history.sfs $(GOLDEN)/alloctest.sfs
	./sfs_alloctest $(GOLDEN)/alloctest.sfs $(GOLDEN)/golden-history.manifest
	@echo "- bigrec (dynamic record buffer, >5 MiB record)"
	./sfs_bigrec $(GOLDEN)/bigrec.sfs
	@echo "- cowtest (WS3 CoW overwrite/truncate/holes on golden-history)"
	cp $(GOLDEN)/golden-history.sfs $(GOLDEN)/cowtest-history.sfs
	./sfs_cowtest $(GOLDEN)/cowtest-history.sfs history
	./sfs_cowcheck.sh $(GOLDEN)/cowtest-history.sfs $(REPO)/target/release
	@echo "- cowtest (WS3 pin acid test on golden-pinned)"
	cp $(GOLDEN)/golden-pinned.sfs $(GOLDEN)/cowtest-pinned.sfs
	./sfs_cowtest $(GOLDEN)/cowtest-pinned.sfs pinned
	./sfs_cowcheck.sh $(GOLDEN)/cowtest-pinned.sfs $(REPO)/target/release
	@echo "- cowtest (WS5 5.2 meta attr write + symlink unit on golden-gcm)"
	cp $(GOLDEN)/golden-gcm.sfs $(GOLDEN)/cowtest-meta.sfs
	./sfs_cowtest $(GOLDEN)/cowtest-meta.sfs meta
	./sfs_cowcheck.sh $(GOLDEN)/cowtest-meta.sfs $(REPO)/target/release
	@echo "- cowtest (WS4 namespace ops on golden-gcm)"
	cp $(GOLDEN)/golden-gcm.sfs $(GOLDEN)/cowtest-ns.sfs
	./sfs_cowtest $(GOLDEN)/cowtest-ns.sfs ns
	./sfs_cowcheck.sh $(GOLDEN)/cowtest-ns.sfs $(REPO)/target/release
	@echo "- cowtest (D-2b re-chunk: grow /big.bin across the 16 MiB band on golden-gcm)"
	cp $(GOLDEN)/golden-gcm.sfs $(GOLDEN)/cowtest-rechunk.sfs
	./sfs_cowtest $(GOLDEN)/cowtest-rechunk.sfs rechunk
	./sfs_cowcheck.sh $(GOLDEN)/cowtest-rechunk.sfs $(REPO)/target/release
	@echo "- triecow (WS8 8.1/8.2: path-CoW catalogs + allocator reuse)"
	cp $(GOLDEN)/golden-gcm.sfs $(GOLDEN)/triecow.sfs
	./sfs_triecow $(GOLDEN)/triecow.sfs
	./sfs_cowcheck.sh $(GOLDEN)/triecow.sfs $(REPO)/target/release
	@echo "- waltest (WS9 9.2: checkpoint fold on golden-wal)"
	cp $(GOLDEN)/golden-wal.sfs $(GOLDEN)/waltest.sfs
	./sfs_waltest $(GOLDEN)/waltest.sfs $(GOLDEN)/golden-wal.manifest
	./sfs_cowcheck.sh $(GOLDEN)/waltest.sfs $(REPO)/target/release
	@echo "- evicttest (WS11 11.1: bands parity + apply on golden-gcm)"
	cp $(GOLDEN)/golden-gcm.sfs $(GOLDEN)/evict-bands.sfs
	./sfs_evicttest $(GOLDEN)/evict-bands.sfs bands $(REPO)/target/release
	./sfs_cowcheck.sh $(GOLDEN)/evict-bands.sfs $(REPO)/target/release
	@echo "- evicttest (WS11 11.1: pin survival + compaction veto on golden-pinned)"
	cp $(GOLDEN)/golden-pinned.sfs $(GOLDEN)/evict-pinned.sfs
	./sfs_evicttest $(GOLDEN)/evict-pinned.sfs pinned $(REPO)/target/release
	./sfs_cowcheck.sh $(GOLDEN)/evict-pinned.sfs $(REPO)/target/release
	@echo "- defragtest (WS11 11.2: fixpoint compaction on golden-gcm)"
	cp $(GOLDEN)/golden-gcm.sfs $(GOLDEN)/defrag.sfs
	./sfs_defragtest $(GOLDEN)/defrag.sfs
	./sfs_cowcheck.sh $(GOLDEN)/defrag.sfs $(REPO)/target/release
	@echo "- trimtest (WS11 11.3: both-slots discard rule)"
	./sfs_trimtest
	@echo "- cowtest signed (WS10 10.2: Fresh-signed CoW/meta/ns records, Rust re-verified)"
	cp $(GOLDEN)/golden-signed-gcm.sfs $(GOLDEN)/cowtest-signed-cow.sfs
	./sfs_cowtest $(GOLDEN)/cowtest-signed-cow.sfs signedcow 5151515151515151515151515151515151515151515151515151515151515151
	./sfs_cowcheck.sh $(GOLDEN)/cowtest-signed-cow.sfs $(REPO)/target/release
	cp $(GOLDEN)/golden-signed-gcm.sfs $(GOLDEN)/cowtest-signed-meta.sfs
	./sfs_cowtest $(GOLDEN)/cowtest-signed-meta.sfs meta 5151515151515151515151515151515151515151515151515151515151515151
	./sfs_cowcheck.sh $(GOLDEN)/cowtest-signed-meta.sfs $(REPO)/target/release
	cp $(GOLDEN)/golden-signed-gcm.sfs $(GOLDEN)/cowtest-signed-ns.sfs
	./sfs_cowtest $(GOLDEN)/cowtest-signed-ns.sfs ns 5151515151515151515151515151515151515151515151515151515151515151
	./sfs_cowcheck.sh $(GOLDEN)/cowtest-signed-ns.sfs $(REPO)/target/release
	@echo "- cowtest writerset (WS10 10.2: owner-member Fresh signing, Rust re-verified)"
	cp $(GOLDEN)/golden-writerset.sfs $(GOLDEN)/cowtest-wset.sfs
	./sfs_cowtest $(GOLDEN)/cowtest-wset.sfs signedcow 7171717171717171717171717171717171717171717171717171717171717171
	./sfs_cowcheck.sh $(GOLDEN)/cowtest-wset.sfs $(REPO)/target/release
	@echo "- defragtest signed (WS10 item 4: relocation PRESERVES signatures)"
	cp $(GOLDEN)/golden-signed-gcm.sfs $(GOLDEN)/defrag-signed.sfs
	./sfs_defragtest $(GOLDEN)/defrag-signed.sfs 5151515151515151515151515151515151515151515151515151515151515151
	./sfs_cowcheck.sh $(GOLDEN)/defrag-signed.sfs $(REPO)/target/release
	@echo "- evicttest signed (WS10 item 4: chain compaction PRESERVES signatures)"
	cp $(GOLDEN)/golden-signed-gcm.sfs $(GOLDEN)/evict-signed.sfs
	./sfs_evicttest $(GOLDEN)/evict-signed.sfs bands $(REPO)/target/release 5151515151515151515151515151515151515151515151515151515151515151
	./sfs_cowcheck.sh $(GOLDEN)/evict-signed.sfs $(REPO)/target/release

# WS6 6.2: end-to-end roundtrip (per cipher × scenario: mutate → kernel-objectcode
# manifest diff → Rust fsck → Rust content/history/attr → both-directions).
roundtrip: sfs_mut sfs_verify golden
	./roundtrip.sh $(GOLDEN) $(REPO)/target/release

# WS6 6.4: seeded differential fuzz — bounded for PR gating (a few seeds ×
# ciphers × ~800 ops). The longer soak is `make fuzz-soak` (documented, manual).
FUZZ_OPS ?= 800
FUZZ_SEEDS ?= 1 2
fuzz: sfs_fuzz sfs_verify golden
	@set -e; for c in none xts gcm; do \
	  for s in $(FUZZ_SEEDS); do \
	    echo "== fuzz cipher=$$c seed=$$s ops=$(FUZZ_OPS) =="; \
	    cp $(GOLDEN)/golden-$$c.sfs $(GOLDEN)/fuzz-$$c-$$s.sfs; \
	    ./sfs_fuzz $(GOLDEN)/fuzz-$$c-$$s.sfs $$s $(FUZZ_OPS) \
	      --manifest $(GOLDEN)/fuzz-$$c-$$s.manifest; \
	    $(REPO)/target/release/sfs-fsck $(GOLDEN)/fuzz-$$c-$$s.sfs >/dev/null; \
	    ./sfs_verify --image $(GOLDEN)/fuzz-$$c-$$s.sfs \
	      $(GOLDEN)/fuzz-$$c-$$s.manifest fuzz-$$c-$$s; \
	  done; \
	done; \
	echo "== fuzz: ALL PASS =="

# Longer soak (manual / nightly): larger op counts, more seeds.
fuzz-soak: sfs_fuzz sfs_verify golden
	@set -e; for c in none xts gcm; do \
	  for s in 1 2 3 4 5 6 7 8; do \
	    echo "== soak cipher=$$c seed=$$s =="; \
	    cp $(GOLDEN)/golden-$$c.sfs $(GOLDEN)/soak-$$c-$$s.sfs; \
	    ./sfs_fuzz $(GOLDEN)/soak-$$c-$$s.sfs $$s 20000 --grow 512 \
	      --manifest $(GOLDEN)/soak-$$c-$$s.manifest; \
	    $(REPO)/target/release/sfs-fsck $(GOLDEN)/soak-$$c-$$s.sfs >/dev/null; \
	    ./sfs_verify --image $(GOLDEN)/soak-$$c-$$s.sfs \
	      $(GOLDEN)/soak-$$c-$$s.manifest soak-$$c-$$s; \
	  done; \
	done; \
	echo "== fuzz-soak: ALL PASS =="

clean:
	rm -f sfs_verify sfs_mkfs sfs_evil sfs_probe sfs_committest sfs_alloctest \
	  sfs_bigrec sfs_cowtest sfs_triecow sfs_waltest sfs_evicttest \
	  sfs_defragtest sfs_trimtest sfs_edtest sfs_xattrtest sfsctl sfs_mut sfs_fuzz
	rm -rf *.dSYM
