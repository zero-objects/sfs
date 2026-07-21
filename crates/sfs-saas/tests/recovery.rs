//! Phase 5 Task 8 — ZK key recovery tests.
//!
//! Six tests as specified in task-8-p5-brief.md:
//!
//! 1. `recovery_code_roundtrip` — correct code recovers key; wrong code → Err.
//! 2. `recovery_is_offline` — signatures require no password/server argument.
//! 3. `recovery_code_high_entropy` — two codes differ; charset/length checks.
//! 4. `recovery_blob_is_opaque_on_server` — stored bytes don't contain raw key.
//! 5. `shamir_k_of_n_reconstructs` — every k-subset rebuilds; <k does not.
//! 6. `shamir_plus_recovery_end_to_end` — split code → reconstruct → recover key.

use sfs_saas::recovery::{
    combine_secret, generate_recovery_code, recover_root_key, split_secret, wrap_root_key_recovery,
};
use sfs_saas::ServerStore;

// ── Test 1: recovery_code_roundtrip ─────────────────────────────────────────

#[test]
fn recovery_code_roundtrip() {
    let code = generate_recovery_code();
    let root_key: [u8; 32] = [0xA5u8; 32];

    // Correct code must recover the original key.
    let blob = wrap_root_key_recovery(&code, &root_key).expect("wrap must succeed");
    let recovered = recover_root_key(&code, &blob).expect("correct code must recover");
    assert_eq!(recovered, root_key, "recovered key must match original");

    // Wrong code must return Err — not a wrong key, not a zero key.
    let wrong_code = generate_recovery_code();
    assert_ne!(code, wrong_code, "two fresh codes must differ (sanity)");
    let result = recover_root_key(&wrong_code, &blob);
    assert!(
        result.is_err(),
        "wrong recovery code must return Err (AEAD tag failure), not a garbage key"
    );
}

// ── Test 2: recovery_is_offline ──────────────────────────────────────────────

/// This test is structural: the function signatures of `wrap_root_key_recovery`
/// and `recover_root_key` do not accept a password or ServerStore argument.
/// If this compiles, the offline property is proven by the type system.
#[test]
fn recovery_is_offline() {
    let code = generate_recovery_code();
    let root_key: [u8; 32] = [0x77u8; 32];

    // wrap_root_key_recovery(code, key) — no password, no server
    let blob = wrap_root_key_recovery(&code, &root_key).expect("wrap");

    // recover_root_key(code, blob) — no password, no server
    let recovered = recover_root_key(&code, &blob).expect("recover");

    assert_eq!(
        recovered, root_key,
        "offline recovery must reproduce the original key"
    );
}

// ── Test 3: recovery_code_high_entropy ──────────────────────────────────────

#[test]
fn recovery_code_high_entropy() {
    let code1 = generate_recovery_code();
    let code2 = generate_recovery_code();

    // Two codes must differ (2^256 space → collision probability is negligible).
    assert_ne!(code1, code2, "two freshly generated codes must differ");

    // Strip hyphens and check the raw Crockford characters.
    let raw: String = code1.chars().filter(|&c| c != '-').collect();

    // Crockford Base32 alphabet: 0-9, A-H, J, K, M, N, P-T, V-Z (no I/L/O/U).
    const CROCKFORD_CHARS: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    for ch in raw.chars() {
        assert!(
            CROCKFORD_CHARS.contains(ch),
            "character '{ch}' is not in the Crockford Base32 alphabet"
        );
    }

    // 32 bytes → ceil(32*8/5) = 52 Crockford characters.
    assert_eq!(
        raw.len(),
        52,
        "32-byte CSPRNG output encodes to exactly 52 Crockford chars"
    );

    // Grouped into 8-char chunks: 52 chars / 8 = 6 full chunks + 1 partial = 7 groups.
    let parts: Vec<&str> = code1.split('-').collect();
    assert_eq!(parts.len(), 7, "code must have 7 hyphen-separated groups");
}

// ── Test 4: recovery_blob_is_opaque_on_server ────────────────────────────────

#[test]
fn recovery_blob_is_opaque_on_server() {
    let mut store = ServerStore::new();
    let account = "alice@example.com";
    let code = generate_recovery_code();
    let root_key: [u8; 32] = [0xBEu8; 32];

    let blob = wrap_root_key_recovery(&code, &root_key).expect("wrap");

    // Store the blob server-side.
    store.put_recovery_blob(account, blob.clone());

    // Retrieve it (server returns bytes verbatim, no decryption).
    let stored = store
        .get_recovery_blob(account)
        .expect("blob must be stored");

    // The raw root key bytes must NOT appear in the stored blob.
    assert!(
        !stored
            .windows(root_key.len())
            .any(|w| w == root_key.as_slice()),
        "stored recovery blob must not contain the raw root key"
    );

    // Account isolation: a different account must not see this blob.
    assert!(
        store.get_recovery_blob("bob@example.com").is_none(),
        "recovery blob must be scoped to the account that stored it"
    );

    // The stored blob must equal what wrap produced (verbatim echo, no server-side transform).
    assert_eq!(stored, blob.as_slice(), "server must echo blob verbatim");
}

// ── Test 5: shamir_k_of_n_reconstructs ──────────────────────────────────────

/// Every k-subset of n=5 shares must reconstruct exactly; any (k-1)-subset must not.
#[test]
fn shamir_k_of_n_reconstructs() {
    let secret: Vec<u8> = (0u8..32).collect(); // 32-byte secret

    // --- (k=3, n=5) ---
    {
        let shares = split_secret(&secret, 3, 5);
        assert_eq!(shares.len(), 5);

        // All 10 combinations of 3 out of 5 must reconstruct exactly.
        let indices: Vec<usize> = (0..5).collect();
        for i in 0..5 {
            for j in (i + 1)..5 {
                for l in (j + 1)..5 {
                    let subset = vec![
                        shares[indices[i]].clone(),
                        shares[indices[j]].clone(),
                        shares[indices[l]].clone(),
                    ];
                    let reconstructed =
                        combine_secret(&subset).expect("3-subset must reconstruct");
                    assert_eq!(
                        reconstructed, secret,
                        "3-subset ({i},{j},{l}) must reconstruct the original secret"
                    );
                }
            }
        }

        // Any 2-subset (< k) must NOT reconstruct the secret.
        // We check all 10 pairs; each must yield a different (wrong) result.
        let mut any_correct = false;
        for i in 0..5 {
            for j in (i + 1)..5 {
                let subset = vec![shares[i].clone(), shares[j].clone()];
                let result = combine_secret(&subset).expect("2-subset combine must not error");
                if result == secret {
                    any_correct = true;
                }
            }
        }
        assert!(
            !any_correct,
            "no 2-subset should reconstruct the secret when k=3"
        );
    }

    // --- (k=5, n=5): all shares required ---
    {
        let secret2: Vec<u8> = vec![0xFF; 16];
        let shares = split_secret(&secret2, 5, 5);
        assert_eq!(shares.len(), 5);

        let all: Vec<_> = shares.to_vec();
        let reconstructed = combine_secret(&all).expect("k=n=5 must reconstruct");
        assert_eq!(reconstructed, secret2, "k=n reconstruction must be exact");

        // 4 shares (< k=5) must NOT reconstruct.
        let four: Vec<_> = shares[..4].to_vec();
        let result = combine_secret(&four).expect("4-subset combine must not error");
        assert_ne!(
            result, secret2,
            "4 shares must not reconstruct when k=5"
        );
    }

    // --- (k=1, n=3): single share is sufficient ---
    {
        let secret3: Vec<u8> = b"hello world!!!!!".to_vec();
        let shares = split_secret(&secret3, 1, 3);
        // Every single share must reconstruct (k=1 means secret IS the constant term).
        for share in &shares {
            let result = combine_secret(std::slice::from_ref(share)).expect("k=1 reconstruct");
            assert_eq!(result, secret3, "k=1: every single share reconstructs");
        }
    }
}

// ── Test 6: shamir_plus_recovery_end_to_end ──────────────────────────────────

#[test]
fn shamir_plus_recovery_end_to_end() {
    // Generate a recovery code and a root key.
    let code = generate_recovery_code();
    let root_key: [u8; 32] = [0xC3u8; 32];

    // Wrap the root key with the recovery code.
    let recovery_blob = wrap_root_key_recovery(&code, &root_key).expect("wrap");

    // Split the recovery code (as raw bytes, after stripping hyphens) into shares.
    let code_bytes: Vec<u8> = code.replace('-', "").into_bytes();
    let n = 5u8;
    let k = 3u8;
    let shares = split_secret(&code_bytes, k, n);
    assert_eq!(shares.len(), usize::from(n));

    // Reconstruct from exactly k shares.
    let k_shares: Vec<_> = shares[..usize::from(k)].to_vec();
    let reconstructed_bytes = combine_secret(&k_shares).expect("k-subset must reconstruct");

    // Rebuild the code string (no hyphens needed — recover_root_key strips them).
    let reconstructed_code =
        String::from_utf8(reconstructed_bytes).expect("code bytes are valid UTF-8");

    // Recover the root key using the reconstructed code.
    let recovered_key =
        recover_root_key(&reconstructed_code, &recovery_blob).expect("recovery must succeed");

    assert_eq!(
        recovered_key, root_key,
        "root key recovered via Shamir reconstruction must equal original"
    );
}
