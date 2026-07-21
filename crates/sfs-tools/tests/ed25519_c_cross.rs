//! WS10 cross-check: signatures produced by the KERNEL's Ed25519 port
//! (`kernel/sfs_ed25519.c`, ref10 via orlp/ed25519) must verify under the
//! Rust byte-authority (`sfs_core::crypto::sign` = ed25519-dalek v2
//! `verify_strict`).
//!
//! The vectors below were emitted by the C core (deterministic RFC 8032
//! signing over fixed seeds/messages). Regenerate with the `gensig` harness in
//! the kernel tools (the historical WS10 note is in git history) — seeds are
//! `seed[i] = t*41 + i*3 + 5`, messages `msg[i] = i*11 + t` of length
//! `t*19 % 98`, t = 0..6. The live per-run direction (dalek-sign → C-verify →
//! C-sign byte-equality) is covered by `kernel/tools/sfs_edtest.c` against
//! `ed25519-vectors.txt`; this test pins the reverse direction inside `cargo
//! test` so a Rust-side regression (e.g. a dalek major bump changing strict
//! semantics) is caught here.

use sfs_core::crypto::sign::{keypair_from_seed, verify};

struct CVec {
    seed: [u8; 32],
    pub_hex: &'static str,
    msg_hex: &'static str,
    sig_hex: &'static str,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn cvec(t: u8, pub_hex: &'static str, msg_hex: &'static str, sig_hex: &'static str) -> CVec {
    CVec {
        seed: core::array::from_fn(|i| (t as usize * 41 + i * 3 + 5) as u8),
        pub_hex,
        msg_hex,
        sig_hex,
    }
}

#[test]
fn c_kernel_signatures_verify_under_dalek() {
    let vectors = [
        cvec(
            0,
            "2cb18b737e300cb4dd26aefc1e5b5557de7f4af3612195843c6343b5ba0d4936",
            "",
            "0039253b7af83727c0754c416df3089ca3123042a0c183e081df23ae1d25514709f3c9c77eb40e92547149995816a946518ca014c6a3dcbc659bf7badb71910b",
        ),
        cvec(
            1,
            "bd8da7edb8c84488e8c9b1e663891e8f4ec847b139d48134198d8921b173e198",
            "010c17222d38434e59646f7a85909ba6b1bcc7",
            "7812bc473065c111356d0d643a26f77a3e9f4e26727d7dc57d200d1d0312b5163eb30d0b4d4eaffbf6bdd73ca75e93b8c949443390fad5d206349b51c200c607",
        ),
        cvec(
            2,
            "125e1fdf570ebc9dcd4b176a491945ea19fc8d0146a822c38f2d737be5ffbce2",
            "020d18232e39444f5a65707b86919ca7b2bdc8d3dee9f4ff0a15202b36414c57626d78838e99",
            "f8e9fda9fb2e1ad675fd50983d8376c3641f4298e44940f74f15a5be128614379f6c8eb9809bfba315fef83b2ed41ad6ffd7e07c5a0c98335ae05d4cbfb00c07",
        ),
        cvec(
            3,
            "f8b1b4b65b1e0711561b391b61b88c8beb7761c91af3f35526f734c7231b4375",
            "030e19242f3a45505b66717c87929da8b3bec9d4dfeaf5000b16212c37424d58636e79848f9aa5b0bbc6d1dce7f2fd08131e29343f4a55606b",
            "85a293816b6824ca9d95ae1fb9b4df5b2b5a44091c2274d5dcfc4085e86e8bb078cc021ea0bac3d38dd5a6edec931eee9df1b477babe2f90dd9d37291d4dfa0c",
        ),
        cvec(
            4,
            "d2be6bae7aac7f77aa31180419f8a9eabe95a4f0fad2468b9a0baca570e792a7",
            "040f1a25303b46515c67727d88939ea9b4bfcad5e0ebf6010c17222d38434e59646f7a85909ba6b1bcc7d2dde8f3fe09141f2a35404b56616c77828d98a3aeb9c4cfdae5f0fb06111c27323d",
            "02513ad0462ebefe832e3718f16f0acbc9aa8837e3cf8f8b484c8968baa66a403e5d0bf5039778cb59b1b313c359eef7e80548c67e5fe7b25c6bf312615ef10c",
        ),
        cvec(
            5,
            "c559602f79fd960d2bdcadd025fab27e95fd0c811fd8b4d8cf3047e7207dddaa",
            "05101b26313c47525d68737e89949faab5c0cbd6e1ecf7020d18232e39444f5a65707b86919ca7b2bdc8d3dee9f4ff0a15202b36414c57626d78838e99a4afbac5d0dbe6f1fc07121d28333e49545f6a75808b96a1acb7c2cdd8e3eef9040f",
            "f70322d0b27b844bb49ba0ace3f4d640afdea5161421c29860c8c7915765e9ec6e0bb45e5fc932cf61bac652d05c710eed87f3cd067cdef22d01d97522ac100f",
        ),
    ];

    for (t, v) in vectors.iter().enumerate() {
        // Seed derivation parity: the C core's pubkey must equal dalek's.
        let (pk, _sk) = keypair_from_seed(&v.seed);
        assert_eq!(
            pk.to_vec(),
            unhex(v.pub_hex),
            "vector {t}: C-derived pubkey != dalek pubkey"
        );

        let msg = unhex(v.msg_hex);
        let sig: [u8; 64] = unhex(v.sig_hex).try_into().unwrap();
        assert!(
            verify(&pk, &msg, &sig),
            "vector {t}: C kernel signature must verify under dalek verify_strict"
        );

        // Tamper: flipped payload byte must be rejected.
        if !msg.is_empty() {
            let mut bad = msg.clone();
            bad[0] ^= 0xff;
            assert!(!verify(&pk, &bad, &sig), "vector {t}: tampered payload accepted");
        }
        // Tamper: flipped signature byte must be rejected.
        let mut badsig = sig;
        badsig[13] ^= 0x04;
        assert!(!verify(&pk, &msg, &badsig), "vector {t}: tampered signature accepted");
    }
}
