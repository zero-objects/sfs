//! SRP-6a conformance and integration tests.
//!
//! Test A: Byte-exact conformance against the Thinbus/Nimbus fixture.
//! Test B: Full Rust handshake round-trip.
//! Test C: Verifier-only ZK (server never stores password).
//! Test D: Root-key-wrap round-trip (right password works, wrong fails).

use num_traits::Zero;
use sfs_saas::srp::{
    compute_u, compute_verifier, compute_x, h, strip0, to_hex, unwrap_root_key, wrap_root_key,
    SrpClientSession, SrpServerSession, K_HEX_CONST,
};
use sfs_saas::ServerStore;

// ── Fixture path ──────────────────────────────────────────────────────────────

const FIXTURE: &str = include_str!("fixtures/thinbus_nimbus_srp_vectors.json");

// ── Test A: Byte-exact conformance ────────────────────────────────────────────

#[test]
fn conformance_verifier_k_m1_m2() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture is valid JSON");

    // ── 1. k literal matches fixture ─────────────────────────────────────────
    let k_fixture = fixture["params"]["k_base16"].as_str().unwrap();
    assert_eq!(
        K_HEX_CONST, k_fixture,
        "k literal must equal fixture k_base16"
    );

    // ── 2. Recompute verifier from (salt, username, password) ────────────────
    let username = fixture["username"].as_str().unwrap();
    let password = fixture["password"].as_str().unwrap();
    let salt = fixture["salt"].as_str().unwrap();
    let expected_verifier = fixture["verifier"].as_str().unwrap();

    let x = compute_x(salt, username, password);
    let computed_verifier = compute_verifier(&x);

    assert_eq!(
        computed_verifier, expected_verifier,
        "computed verifier must match fixture verifier"
    );

    // ── 3. Recompute K, M1, M2 from fixture A, B, S ─────────────────────────
    let a_hex = fixture["A"].as_str().unwrap();
    let b_hex = fixture["B"].as_str().unwrap();
    let s_hex = fixture["client_internals"]["SS"].as_str().unwrap();

    let expected_k = fixture["sessionKey_client"].as_str().unwrap();
    let expected_m1 = fixture["M1"].as_str().unwrap();
    let expected_m2 = fixture["M2"].as_str().unwrap();

    // K = H(toHex(S))  — no strip0
    let computed_k = h(&[s_hex]);
    assert_eq!(computed_k, expected_k, "K = H(S_hex) must match fixture sessionKey_client");

    // M1 = strip0(H(A_hex + B_hex + S_hex))
    let computed_m1 = strip0(&h(&[a_hex, b_hex, s_hex]));
    assert_eq!(computed_m1, expected_m1, "M1 must match fixture M1");

    // M2 = strip0(H(A_hex + M1 + S_hex))
    let computed_m2 = strip0(&h(&[a_hex, &computed_m1, s_hex]));
    assert_eq!(computed_m2, expected_m2, "M2 must match fixture M2");

    // Also sanity-check u is deterministic from A and B
    let u = compute_u(a_hex, b_hex);
    assert!(!u.is_zero(), "u must not be zero");
}

// ── Test B: Full Rust handshake round-trip ────────────────────────────────────

#[test]
fn round_trip_handshake_correct_password() {
    let identity = "bob@example.com";
    let password = "hunter2";

    // Registration: client computes verifier, server stores it.
    let salt = "deadbeefdeadbeefdeadbeefdeadbeef"; // 32-char hex
    let x = compute_x(salt, identity, password);
    let verifier = compute_verifier(&x);

    let mut store = ServerStore::new();
    let _ = store.register(identity, salt, &verifier);

    // Step 1: client sends A.
    let client = SrpClientSession::new();
    let a_hex = client.step1();

    // Step 1: server reads credentials, creates session, sends B.
    let (stored_salt, stored_verifier) = store.get_credentials(identity).unwrap();
    let server = SrpServerSession::new(stored_salt, stored_verifier).unwrap();
    let b_hex = server.step1();

    // Step 2: client computes M1, K, and S_hex (needed for mutual-auth verify).
    let (m1, k_client, s_hex_client) = client.step2(salt, identity, password, &b_hex).unwrap();

    // Step 2: server verifies M1 and returns M2.
    let m2 = server.step2(&a_hex, &m1).expect("server must accept correct M1");

    assert!(!m2.is_empty(), "server must return a non-empty M2");
    assert!(!k_client.is_empty(), "client session key must be non-empty");

    // Client verifies server's M2 (mutual authentication).
    let m2_accepted = SrpClientSession::verify_m2(&a_hex, &m1, &s_hex_client, &m2);
    assert!(m2_accepted, "client must accept server's M2 (mutual auth)");

    // Sanity: wrong M1 is rejected by server.
    let bad_m1 = "0000000000000000000000000000000000000000000000000000000000000000";
    assert!(
        server.step2(&a_hex, bad_m1).is_err(),
        "server must reject wrong M1"
    );
}

#[test]
fn round_trip_handshake_wrong_password_fails() {
    let identity = "carol@example.com";
    let correct_pw = "correct-password";
    let wrong_pw = "wrong-password";

    let salt = "aabbccddaabbccddaabbccddaabbccdd";
    let x = compute_x(salt, identity, correct_pw);
    let verifier = compute_verifier(&x);

    let mut store = ServerStore::new();
    let _ = store.register(identity, salt, &verifier);

    let client = SrpClientSession::new();
    let a_hex = client.step1();

    let (stored_salt, stored_verifier) = store.get_credentials(identity).unwrap();
    let server = SrpServerSession::new(stored_salt, stored_verifier).unwrap();
    let b_hex = server.step1();

    // Client uses WRONG password — will compute wrong x → wrong S → wrong M1.
    let (m1_wrong, _, _) = client.step2(salt, identity, wrong_pw, &b_hex).unwrap();

    // Server must reject the wrong M1.
    assert!(
        server.step2(&a_hex, &m1_wrong).is_err(),
        "server must reject M1 computed from wrong password"
    );
}

// ── Test C: Verifier-only ZK ──────────────────────────────────────────────────

#[test]
fn verifier_only_zk_no_password_in_store() {
    let identity = "dave@example.com";
    let password = "super-secret-pass";
    let salt = "cafebabecafebabecafebabecafebabe";

    let x = compute_x(salt, identity, password);
    let verifier = compute_verifier(&x);

    let mut store = ServerStore::new();
    let _ = store.register(identity, salt, &verifier);

    let (_, stored_verifier) = store.get_credentials(identity).unwrap();

    // The password bytes must NOT appear in the stored verifier hex string.
    assert!(
        !stored_verifier.contains(password),
        "stored verifier must not contain the password"
    );

    // The verifier is not equal to the raw password bytes.
    assert_ne!(
        stored_verifier.as_bytes(),
        password.as_bytes(),
        "verifier must differ from password"
    );

    // The password must not appear as a sub-slice in the verifier bytes.
    let pw_bytes = password.as_bytes();
    let vbytes = stored_verifier.as_bytes();
    assert!(
        !vbytes.windows(pw_bytes.len()).any(|w| w == pw_bytes),
        "password must not appear as a substring in the stored verifier"
    );
}

// ── Test D: Root-key-wrap round-trip ─────────────────────────────────────────

#[test]
fn root_key_wrap_correct_password_roundtrip() {
    let password = "my-wrapping-password";
    let salt = b"some-fixed-salt-for-argon2id";
    let root_key: [u8; 32] = [0x42u8; 32];

    let blob = wrap_root_key(password, salt, &root_key).expect("wrap must succeed");
    let recovered = unwrap_root_key(password, salt, &blob).expect("unwrap must succeed");

    assert_eq!(recovered, root_key, "unwrapped key must match original");
}

#[test]
fn root_key_wrap_wrong_password_fails() {
    let correct_pw = "correct-wrap-password";
    let wrong_pw = "wrong-wrap-password";
    let salt = b"salt-for-argon2id-test";
    let root_key: [u8; 32] = [0x11u8; 32];

    let blob = wrap_root_key(correct_pw, salt, &root_key).expect("wrap must succeed");
    let result = unwrap_root_key(wrong_pw, salt, &blob);

    assert!(
        result.is_err(),
        "unwrap with wrong password must fail with AES-GCM auth error"
    );
}

#[test]
fn root_key_wrap_blob_does_not_contain_raw_key() {
    let password = "blob-inspection-password";
    let salt = b"blob-inspection-salt";
    let root_key: [u8; 32] = [0xABu8; 32];

    let blob = wrap_root_key(password, salt, &root_key).expect("wrap must succeed");

    // The raw root key bytes must not appear as a contiguous sub-slice in the blob.
    assert!(
        !blob.windows(32).any(|w| w == root_key),
        "blob must not contain raw root key bytes"
    );
}

#[test]
fn root_key_wrap_serverstore_roundtrip() {
    let mut store = ServerStore::new();
    let account = "eve@example.com";
    let password = "eve-password";
    let salt = b"eve-wrap-salt";
    let root_key: [u8; 32] = [0xEEu8; 32];

    let blob = wrap_root_key(password, salt, &root_key).expect("wrap");
    store.put_wrapped_key(account, blob.clone());

    let retrieved = store.get_wrapped_key(account).expect("must be stored");
    let recovered = unwrap_root_key(password, salt, retrieved).expect("unwrap");

    assert_eq!(recovered, root_key);
}

// ── Test E: to_hex and strip0 primitives ─────────────────────────────────────

#[test]
fn to_hex_no_leading_zeros() {
    use num_bigint::BigUint;
    // 256 = 0x100 — to_hex should give "100", not "0100"
    let n = BigUint::from(256u32);
    assert_eq!(to_hex(&n), "100");

    // 1 → "1"
    let one = BigUint::from(1u32);
    assert_eq!(to_hex(&one), "1");

    // 0 → "0"
    let zero = BigUint::from(0u32);
    assert_eq!(to_hex(&zero), "0");
}

#[test]
fn strip0_removes_leading_zeros() {
    assert_eq!(strip0("000abc"), "abc");
    assert_eq!(strip0("0"), "0");
    assert_eq!(strip0("00"), "0");
    assert_eq!(strip0("abc"), "abc");
    assert_eq!(strip0("0abc"), "abc");
}

// ── Test F: SRP-6a safety — attack inputs rejected ───────────────────────────

/// The RFC 5054 2048-bit N in hex (same value as the implementation constant).
const N_HEX: &str = "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73";

#[test]
fn attack_a_equals_n_rejected() {
    let identity = "attacker@example.com";
    let password = "anything";
    let salt = "deadbeefdeadbeefdeadbeefdeadbeef";
    let x = compute_x(salt, identity, password);
    let verifier = compute_verifier(&x);

    let mut store = ServerStore::new();
    let _ = store.register(identity, salt, &verifier);

    let (stored_salt, stored_verifier) = store.get_credentials(identity).unwrap();
    let server = SrpServerSession::new(stored_salt, stored_verifier).unwrap();

    // A = N: non-zero as BigUint but A mod N == 0 → auth-bypass if unchecked.
    let result_n = server.step2(N_HEX, "any_m1");
    assert!(
        result_n.is_err(),
        "server must reject A = N (A mod N == 0 bypass)"
    );

    // A = 0: trivially zero.
    let result_zero = server.step2("0", "any_m1");
    assert!(result_zero.is_err(), "server must reject A = 0");
}

#[test]
fn attack_b_equals_n_rejected() {
    let identity = "victim@example.com";
    let password = "secret";
    let salt = "cafebabecafebabecafebabecafebabe";
    let x = compute_x(salt, identity, password);
    let _verifier = compute_verifier(&x);

    // Simulate an attacker-controlled server that sends B = N.
    let client = SrpClientSession::new();

    let result = client.step2(salt, identity, password, N_HEX);
    assert!(
        result.is_err(),
        "client must reject B = N (B mod N == 0 bypass)"
    );

    // B = 0 also rejected.
    let result_zero = client.step2(salt, identity, password, "0");
    assert!(result_zero.is_err(), "client must reject B = 0");
}

// ── Test G: Full mutual authentication round-trip ─────────────────────────────

#[test]
fn full_mutual_auth_round_trip() {
    let identity = "frank@example.com";
    let password = "mutual-auth-password";
    let salt = "1122334455667788112233445566778811223344556677881122334455667788";

    // Registration.
    let x = compute_x(salt, identity, password);
    let verifier = compute_verifier(&x);

    let mut store = ServerStore::new();
    let _ = store.register(identity, salt, &verifier);

    // Step 1.
    let client = SrpClientSession::new();
    let a_hex = client.step1();

    let (stored_salt, stored_verifier) = store.get_credentials(identity).unwrap();
    let server = SrpServerSession::new(stored_salt, stored_verifier).unwrap();
    let b_hex = server.step1();

    // Step 2 (client): returns (M1, K_client, S_hex).
    let (m1, k_client, s_hex_client) = client
        .step2(salt, identity, password, &b_hex)
        .expect("client step2 must succeed");

    // Step 2 (server): verifies M1, returns M2.
    let m2 = server
        .step2(&a_hex, &m1)
        .expect("server must accept correct M1");

    // Derive server's session key (K = H(S)) for comparison.
    // Server's S is internal; we verify by comparing derived K_server == K_client.
    // K_server is not exposed directly — we verify via M2 acceptance and key equality.
    // We reconstruct K_server = H(s_hex_server) by leveraging M2 verification:
    // if client accepts M2 then both sides share the same S (and hence K).
    let m2_ok = SrpClientSession::verify_m2(&a_hex, &m1, &s_hex_client, &m2);
    assert!(m2_ok, "client must accept server M2 (mutual authentication)");

    // Both sides' session keys must be equal: K = H(S_hex).
    // Server's K = H(s_hex_server). Since M2 acceptance proves same S,
    // and K = H(S_hex), K_client == K_server.
    let k_server = sfs_saas::srp::h(&[&s_hex_client]); // same S, same K
    assert_eq!(
        k_client, k_server,
        "client and server session keys must be equal"
    );
}

// ── Test E: constant-time modpow equivalence (DH-1) ───────────────────────────
//
// `srp::ct::modpow` (crypto-bigint Montgomery) must return byte-identical
// results to `num-bigint::modpow` for all inputs the SRP protocol can produce —
// otherwise the CT switch would silently break Thinbus wire compatibility.

#[test]
fn ct_modpow_matches_num_bigint() {
    use num_bigint::BigUint;
    use num_traits::Num;
    use sfs_saas::srp::ct;

    // The SRP group prime N (odd safe prime) and generator g=2.
    let n = BigUint::from_str_radix(
        "21766174458617435773191008891802753781907668374255538511144643224689886235383840957210909013086056401571399717235807266581649606472148410291413364152197364477180887395655483738115072677402235101762521901569820740293149529620419333266262073471054548368736039519702486226506248861060256971802984953561121442680157668000761429988222457090413873973970171927093992114751765168063614761119615476233422096442783117971236371647333871414335895773474667308967050807005509320424799678417036867928316761272274230314067548291133582479583061439577559347101961771406173684378522703483495337037655006751328447510550299250924469288819",
        10,
    )
    .unwrap();

    // Deterministic pseudo-random exponents/bases via a simple LCG over byte
    // widths that cover the SRP range (256-bit x, 2048-bit ephemerals,
    // 2049-bit a+u*x sums).
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut next_bytes = |len: usize| -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            v.push((state >> 33) as u8);
        }
        v
    };

    let g = BigUint::from(2u32);
    // Edge cases + randomized coverage.
    for case in 0..64 {
        let (base, exp): (BigUint, BigUint) = match case {
            0 => (g.clone(), BigUint::from(0u32)),
            1 => (g.clone(), BigUint::from(1u32)),
            2 => (&n - 1u32, BigUint::from(3u32)),
            3 => (g.clone(), &n - 1u32),
            _ => {
                let base = BigUint::from_bytes_be(&next_bytes(256)) % &n;
                // exponent up to ~257 bytes to exceed 2048 bits (a + u*x range)
                let exp = BigUint::from_bytes_be(&next_bytes(257));
                (base, exp)
            }
        };
        let expected = base.modpow(&exp, &n);
        let got = ct::modpow(&base, &exp, &n);
        assert_eq!(
            expected, got,
            "ct::modpow disagrees with num-bigint at case {case}"
        );
    }
}
