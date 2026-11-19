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

#[test]
fn attack_oversized_verifier_no_panic() {
    // The verifier is client-supplied at `/v1/register` (and credential update)
    // and stored as-is.  A verifier >= 2^2048 must not panic the server's
    // `v^u` step (`ct::modpow` encodes its base as a fixed U2048).
    let salt = "deadbeefdeadbeefdeadbeefdeadbeef";
    let verifier = "f".repeat(600);
    let server = SrpServerSession::new(salt, &verifier).unwrap();
    let client = SrpClientSession::new();
    let result = server.step2(&client.step1(), "any_m1");
    assert!(
        result.is_err(),
        "a forged M1 must not authenticate against an oversized verifier"
    );
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

// ── Test F: ct::modpow at full operand width (crypto-bigint 0.7) ──────────────
//
// `ct::modpow` encodes modulus and base as U2048 and the exponent as U4096.
// Test E stays within the SRP range (exponents up to ~2056 bits).  This test
// drives every operand to its full width — 2048-bit moduli with the top bit set
// (the SRP prime, 2^2048-1, a random odd one), bases up to 2^2048-1 (also
// >= modulus), exponents up to 2^4096-1 — against num-bigint's `modpow`.
// Guards the crypto-bigint 0.5 -> 0.7 migration (RUSTSEC-2026-0387).

#[test]
fn ct_modpow_full_width_matches_num_bigint() {
    use num_bigint::BigUint;
    use num_traits::{Num, One};
    use sfs_saas::srp::ct;

    let n_srp = BigUint::from_str_radix(
        "21766174458617435773191008891802753781907668374255538511144643224689886235383840957210909013086056401571399717235807266581649606472148410291413364152197364477180887395655483738115072677402235101762521901569820740293149529620419333266262073471054548368736039519702486226506248861060256971802984953561121442680157668000761429988222457090413873973970171927093992114751765168063614761119615476233422096442783117971236371647333871414335895773474667308967050807005509320424799678417036867928316761272274230314067548291133582479583061439577559347101961771406173684378522703483495337037655006751328447510550299250924469288819",
        10,
    )
    .unwrap();
    assert_eq!(n_srp.bits(), 2048);

    let mut state: u64 = 0xD1B54A32D192ED03;
    let mut next_bytes = |len: usize| -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            v.push((state >> 33) as u8);
        }
        v
    };

    let one = BigUint::one();
    let max2048 = (&one << 2048u32) - 1u32;
    let max4096 = (&one << 4096u32) - 1u32;
    let bit4095 = &one << 4095u32;
    let rand_mod = BigUint::from_bytes_be(&next_bytes(256)) | (&one << 2047u32) | &one;
    assert_eq!(rand_mod.bits(), 2048);

    for (mi, n) in [n_srp, max2048.clone(), rand_mod].iter().enumerate() {
        let mut cases: Vec<(BigUint, BigUint)> = vec![
            (BigUint::from(0u32), one.clone()),
            (BigUint::from(0u32), max4096.clone()),
            (one.clone(), max4096.clone()),
            (BigUint::from(2u32), max4096.clone()),
            (n - 1u32, max4096.clone()),
            (n - 1u32, &max4096 - 1u32),
            (BigUint::from(2u32), bit4095.clone()),
            // base not reduced mod n (ct::modpow accepts any base < 2^2048)
            (max2048.clone(), max4096.clone()),
        ];
        for _ in 0..4 {
            let base = BigUint::from_bytes_be(&next_bytes(256)) % n;
            let exp = BigUint::from_bytes_be(&next_bytes(512)) | &bit4095;
            cases.push((base, exp));
        }
        for (ci, (base, exp)) in cases.iter().enumerate() {
            assert!(base.bits() <= 2048 && exp.bits() <= 4096);
            let expected = base.modpow(exp, n);
            let got = ct::modpow(base, exp, n);
            assert_eq!(
                expected, got,
                "ct::modpow disagrees with num-bigint at modulus {mi}, case {ci}"
            );
        }
    }
}

// ── Test G: ct::modpow against RFC 5054 Appendix B ────────────────────────────
//
// Fixed published vectors (1024-bit group, SHA-1 k/u/x).  Runs every SRP-6a
// exponentiation of the appendix through `ct::modpow`: v, A, B, and the
// premaster secret S from both the server and the client side.  The 1024-bit
// modulus also covers a modulus shorter than the U2048 container.

#[test]
fn ct_modpow_rfc5054_appendix_b() {
    use num_bigint::BigUint;
    use sfs_saas::srp::ct;

    fn hx(s: &str) -> BigUint {
        let digits: String = s.split_whitespace().collect();
        BigUint::parse_bytes(digits.as_bytes(), 16).expect("valid hex")
    }

    let n = hx("EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
                9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
                8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
                7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
                FD5138FE 8376435B 9FC61D2F C0EB06E3");
    let g = BigUint::from(2u32);
    let k = hx("7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F");
    let x = hx("94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124");
    let v = hx("7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812
                9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5
                C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5
                EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78
                E955A5E2 9E7AB245 DB2BE315 E2099AFB");
    let a = hx("60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393");
    let b = hx("E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20");
    let a_pub = hx("61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
                    4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
                    8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
                    BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
                    B349EF5D 76988A36 72FAC47B 0769447B");
    let b_pub = hx("BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011
                    BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99
                    6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA
                    37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE
                    EB4012B7 D7665238 A8E3FB00 4B117B58");
    let u = hx("CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019");
    let s = hx("B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D
                233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C
                41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F
                3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D
                C346D7E4 74B29EDE 8A469FFE CA686E5A");

    // v = g^x mod N
    assert_eq!(ct::modpow(&g, &x, &n), v, "v");
    // A = g^a mod N
    assert_eq!(ct::modpow(&g, &a, &n), a_pub, "A");
    // B = (k*v + g^b) mod N
    assert_eq!((&k * &v + ct::modpow(&g, &b, &n)) % &n, b_pub, "B");
    // Server: S = (A * v^u)^b mod N
    let av = (&a_pub * ct::modpow(&v, &u, &n)) % &n;
    assert_eq!(ct::modpow(&av, &b, &n), s, "S (server)");
    // Client: S = (B - k*g^x)^(a + u*x) mod N
    let kgx = (&k * ct::modpow(&g, &x, &n)) % &n;
    let base = (&b_pub + &n - kgx) % &n;
    assert_eq!(ct::modpow(&base, &(&a + &u * &x), &n), s, "S (client)");
}
