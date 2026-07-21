// SPDX-License-Identifier: GPL-2.0
/*
 * sfs_xattrtest — v3 ATTR xattr codec gate for kernel/sfs_attr.c (D3).
 *
 * Reads the Rust-generated known-answer vectors (sfs-mkgolden →
 * xattr-vectors.txt: BASE / NAME / SET / REMOVE / EMPTY, all attr.rs-encoded)
 * and proves the C codec byte-parity:
 *   - sfs_attr_parse accepts the v3 BASE blob (getattr never breaks);
 *   - sfs_xattr_get returns each NAME's exact value;
 *   - sfs_xattr_list returns the sorted NUL-separated names;
 *   - sfs_xattr_reencode(set/remove) reproduces the SET/REMOVE/EMPTY blobs
 *     byte-for-byte (the strongest cross-implementation check);
 *   - structural fault + size-ceiling paths fail closed.
 *
 * Usage: sfs_xattrtest <goldendir>   (reads <goldendir>/xattr-vectors.txt)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../sfs_format.h"
#include "../sfs_meta.h"

static int fails;

#define CHECK(cond, ...)                                                  \
	do {                                                              \
		if (!(cond)) {                                            \
			printf("  FAIL: ");                              \
			printf(__VA_ARGS__);                              \
			printf("\n");                                    \
			fails++;                                         \
		}                                                        \
	} while (0)

/* hex → bytes; returns length, or -1 on a malformed string. */
static int unhex(const char *s, u8 *out, u32 cap)
{
	u32 n = 0;
	while (s[0] && s[1] && s[0] != ' ' && s[0] != '\n') {
		unsigned int b;
		if (n >= cap || sscanf(s, "%2x", &b) != 1)
			return -1;
		out[n++] = (u8)b;
		s += 2;
	}
	return (int)n;
}

/* One BASE blob + derived expectations, filled from the vector file. */
static u8 base[4096];
static u32 base_len;

static void test_parse_and_get_list(void)
{
	struct sfs_attr at;
	u32 kind = 99;
	u8 val[256];
	u32 vlen = 0;
	char names[256];
	u32 nlen = 0;
	int r;

	/* Parse must accept the v3 blob and report a regular file. */
	r = sfs_attr_parse(base, base_len, &at, &kind);
	CHECK(r == 0, "sfs_attr_parse(v3) returned %d", r);
	CHECK(kind == SFS_ATTR_KIND_FILE, "kind=%u (want FILE)", kind);
	CHECK(at.mode == 0100644u, "mode=%o", at.mode);

	/* list: sorted, NUL-separated "user.author\0user.comment\0". */
	r = sfs_xattr_list(base, base_len, names, sizeof(names), &nlen);
	CHECK(r == 0, "list returned %d", r);
	{
		const char want[] = "user.author\0user.comment\0";
		CHECK(nlen == sizeof(want) - 1, "list len=%u want=%zu", nlen,
		      sizeof(want) - 1);
		CHECK(memcmp(names, want, nlen) == 0, "list bytes mismatch");
	}

	/* get a missing name → -ENODATA; a size probe (cap 0) sets vlen. */
	r = sfs_xattr_get(base, base_len, "user.missing", 12, val, sizeof(val),
			  &vlen);
	CHECK(r == -ENODATA, "get(missing) returned %d", r);
	r = sfs_xattr_get(base, base_len, "user.author", 11, NULL, 0, &vlen);
	CHECK(r == -ERANGE && vlen == 6, "get probe: r=%d vlen=%u", r, vlen);
	r = sfs_xattr_get(base, base_len, "user.author", 11, val, sizeof(val),
			  &vlen);
	CHECK(r == 0 && vlen == 6 && memcmp(val, "sandra", 6) == 0,
	      "get(user.author) r=%d vlen=%u", r, vlen);
}

/* Re-encode a SET/REMOVE against BASE and compare to the Rust result blob. */
static void test_reencode(const char *op, const char *name,
			  const u8 *val, u32 val_len,
			  const u8 *want, u32 want_len)
{
	u8 out[4096];
	u32 out_len = 0;
	int r = sfs_xattr_reencode(base, base_len, name, (u32)strlen(name),
				   val, val_len, out, sizeof(out), &out_len);

	CHECK(r == 0, "%s %s: reencode returned %d", op, name, r);
	CHECK(out_len == want_len, "%s %s: len %u != %u", op, name, out_len,
	      want_len);
	CHECK(out_len == want_len && memcmp(out, want, want_len) == 0,
	      "%s %s: bytes differ from Rust", op, name);
}

static void test_negatives(void)
{
	u8 buf[4096];
	u32 out_len = 0;
	u8 big[SFS_XATTR_MAX_TOTAL + 16];
	int r;

	/* Remove a name that is not present → -ENODATA. */
	r = sfs_xattr_reencode(base, base_len, "user.nope", 9, NULL, 0,
			       buf, sizeof(buf), &out_len);
	CHECK(r == -ENODATA, "remove(missing) returned %d", r);

	/* Set a value over the size ceiling → -E2BIG. */
	memset(big, 0, sizeof(big));
	r = sfs_xattr_reencode(base, base_len, "user.big", 8, big, sizeof(big),
			       buf, sizeof(buf), &out_len);
	CHECK(r == -E2BIG, "set(oversized) returned %d", r);

	/* A truncated BASE must fail closed at every length (no OOB / crash). */
	for (u32 len = 0; len < base_len; len++) {
		struct sfs_attr at;
		u32 kind;
		(void)sfs_attr_parse(base, len, &at, &kind);
		(void)sfs_xattr_get(base, len, "user.author", 11, buf,
				    sizeof(buf), &out_len);
		(void)sfs_xattr_list(base, len, (char *)buf, sizeof(buf),
				     &out_len);
	}
}

int main(int argc, char **argv)
{
	char path[1024];
	FILE *f;
	char line[16384];
	u8 want[4096];
	int want_len;

	if (argc < 2) {
		fprintf(stderr, "usage: sfs_xattrtest <goldendir>\n");
		return 2;
	}
	snprintf(path, sizeof(path), "%s/xattr-vectors.txt", argv[1]);
	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "cannot open %s\n", path);
		return 2;
	}

	printf("== xattrtest: %s ==\n", path);
	while (fgets(line, sizeof(line), f)) {
		char tag[32], name[256], hexa[8192], hexb[8192];
		if (line[0] == '#' || line[0] == '\n')
			continue;
		if (sscanf(line, "%31s", tag) != 1)
			continue;

		if (strcmp(tag, "BASE") == 0) {
			sscanf(line, "%31s %8191s", tag, hexa);
			base_len = (u32)unhex(hexa, base, sizeof(base));
			test_parse_and_get_list();
		} else if (strcmp(tag, "NAME") == 0) {
			u8 val[256], exp[256];
			u32 vlen = 0;
			int explen;
			sscanf(line, "%31s %255s %8191s", tag, name, hexa);
			explen = unhex(hexa, exp, sizeof(exp));
			int r = sfs_xattr_get(base, base_len, name,
					      (u32)strlen(name), val,
					      sizeof(val), &vlen);
			CHECK(r == 0 && (int)vlen == explen &&
				      memcmp(val, exp, vlen) == 0,
			      "NAME %s: r=%d vlen=%u", name, r, vlen);
		} else if (strcmp(tag, "SET") == 0) {
			u8 val[4096];
			int vl;
			sscanf(line, "%31s %255s %8191s %8191s", tag, name,
			       hexa, hexb);
			vl = unhex(hexa, val, sizeof(val));
			want_len = unhex(hexb, want, sizeof(want));
			test_reencode("SET", name, val, (u32)vl, want,
				      (u32)want_len);
		} else if (strcmp(tag, "REMOVE") == 0) {
			sscanf(line, "%31s %255s %8191s", tag, name, hexa);
			want_len = unhex(hexa, want, sizeof(want));
			test_reencode("REMOVE", name, NULL, 0, want,
				      (u32)want_len);
		} else if (strcmp(tag, "EMPTY") == 0) {
			/* Remove BOTH keys → must land on the v2 EMPTY blob. */
			u8 mid[4096];
			u32 mid_len = 0;
			int r;
			sscanf(line, "%31s %8191s", tag, hexa);
			want_len = unhex(hexa, want, sizeof(want));
			r = sfs_xattr_reencode(base, base_len, "user.author",
					       11, NULL, 0, mid, sizeof(mid),
					       &mid_len);
			CHECK(r == 0, "EMPTY step1 r=%d", r);
			/* second remove from the intermediate blob */
			u8 out[4096];
			u32 out_len = 0;
			r = sfs_xattr_reencode(mid, mid_len, "user.comment", 12,
					       NULL, 0, out, sizeof(out),
					       &out_len);
			CHECK(r == 0 && (int)out_len == want_len &&
				      memcmp(out, want, want_len) == 0,
			      "EMPTY: v2 blob mismatch (r=%d len=%u)", r,
			      out_len);
		}
	}
	fclose(f);
	test_negatives();

	if (fails) {
		printf("== xattrtest: FAIL (%d) ==\n", fails);
		return 1;
	}
	printf("== xattrtest: PASS ==\n");
	return 0;
}
