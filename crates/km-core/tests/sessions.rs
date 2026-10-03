// Property tests need proptest, which runs natively; tests/wasm.rs covers the
// same flows inside a WebAssembly runtime.
#![cfg(not(target_arch = "wasm32"))]

mod common;

use common::*;
use km_core::{CoreError, LocalDevice, MasterKey};
use proptest::prelude::*;

#[test]
fn first_message_reply_and_conversation() {
    let mut alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);

    let env = send(&mut alice, &mut bob, "hi bob");
    let got = receive(&mut bob, &alice, &env).unwrap();
    assert_eq!(text_of(&got), "hi bob");
    assert_eq!(got.sender.user_id, 1);
    assert_eq!(got.sender.device_id, 101);

    // Bob replies on the session Alice started (no prekey needed).
    let env = send(&mut bob, &mut alice, "hey alice");
    assert_eq!(text_of(&receive(&mut alice, &bob, &env).unwrap()), "hey alice");

    for i in 0..50 {
        let (from, to) = if i % 3 == 0 { (&mut bob, &mut alice) } else { (&mut alice, &mut bob) };
        let env = send(from, to, &format!("message {i}"));
        let from_ref: &common::Person = from;
        assert_eq!(text_of(&receive(to, from_ref, &env).unwrap()), format!("message {i}"));
    }
}

#[test]
fn exhausted_one_time_keys_fall_back() {
    let mut bob = Person::new(2, 202);
    bob.prekeys.retain(|p| p.fallback);
    let mut alice = Person::new(1, 101);
    let env = send(&mut alice, &mut bob, "via fallback");
    assert_eq!(text_of(&receive(&mut bob, &alice, &env).unwrap()), "via fallback");
}

#[test]
fn a_prekey_not_signed_by_the_device_is_refused() {
    let mut alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let to = alice.trust_device_of(&bob).unwrap();
    let mut forged = bob.claim_prekey();
    forged.key[0] ^= 1;
    assert_eq!(alice.device.encrypt(&to, Some(&forged), &text("x")), Err(CoreError::BadSignature));
}

#[test]
fn replay_and_tampering_never_yield_a_second_plaintext() {
    let mut alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let env = send(&mut alice, &mut bob, "once");
    assert!(receive(&mut bob, &alice, &env).is_ok());
    assert!(receive(&mut bob, &alice, &env).is_err(), "replay must fail");

    let mut env = send(&mut alice, &mut bob, "tamper me");
    let mid = env.len() / 2;
    env[mid] ^= 0x40;
    assert!(receive(&mut bob, &alice, &env).is_err());
}

#[test]
fn an_envelope_only_opens_on_its_device() {
    let mut alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let mut carol = Person::new(3, 303);
    let env = send(&mut alice, &mut bob, "for bob");
    assert_eq!(receive(&mut carol, &alice, &env), Err(CoreError::Undecryptable));
}

#[test]
fn a_forged_sender_field_does_not_decrypt() {
    // Mallory seals an envelope to Bob claiming to be Alice's device. The seal
    // opens (anyone can seal to Bob), but Mallory's Olm session is bound to
    // Mallory's identity key, not Alice's, so it must fail.
    let alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let mut mallory = Person::new(1, 101); // same ids as Alice, different keys
    let to = mallory.trust_device_of(&bob).unwrap();
    let pk = bob.claim_prekey();
    let env = mallory.device.encrypt(&to, Some(&pk), &text("i am alice")).unwrap();
    assert_eq!(receive(&mut bob, &alice, &env), Err(CoreError::Undecryptable));
}

#[test]
fn unknown_sender_is_reported_not_guessed() {
    let mut alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let env = send(&mut alice, &mut bob, "who am i");
    let r = bob.device.decrypt(&env, |_, _| None);
    assert_eq!(r, Err(CoreError::UnknownSender { user_id: 1, device_id: 101 }));
}

#[test]
fn snapshot_restore_continues_the_conversation() {
    let mut alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let env = send(&mut alice, &mut bob, "before");
    receive(&mut bob, &alice, &env).unwrap();

    let snap = bob.device.snapshot().unwrap();
    bob.device = LocalDevice::restore(&snap).unwrap();
    let snap = alice.device.snapshot().unwrap();
    alice.device = LocalDevice::restore(&snap).unwrap();

    let env = send(&mut bob, &mut alice, "after restore");
    assert_eq!(text_of(&receive(&mut alice, &bob, &env).unwrap()), "after restore");
    let env = send(&mut alice, &mut bob, "and back");
    assert_eq!(text_of(&receive(&mut bob, &alice, &env).unwrap()), "and back");
    // Dedup memory survives a restore too.
    assert!(receive(&mut bob, &alice, &env).is_err());
}

#[test]
fn a_redelivered_envelope_is_a_duplicate_even_after_the_ratchet_moved_on() {
    // The app stored and saved a message but stopped before acknowledging
    // it, so the server sends it again after several more.
    let mut alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let first = send(&mut alice, &mut bob, "first");
    receive(&mut bob, &alice, &first).unwrap();
    let reply = send(&mut bob, &mut alice, "reply");
    receive(&mut alice, &bob, &reply).unwrap();
    for i in 0..3 {
        let env = send(&mut alice, &mut bob, &format!("more {i}"));
        receive(&mut bob, &alice, &env).unwrap();
    }
    let snap = bob.device.snapshot().unwrap();
    bob.device = LocalDevice::restore(&snap).unwrap();
    assert_eq!(receive(&mut bob, &alice, &first).err(), Some(km_core::CoreError::Duplicate));
}

#[test]
fn desync_recovery_with_a_fresh_session() {
    let mut alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let env = send(&mut alice, &mut bob, "one");
    receive(&mut bob, &alice, &env).unwrap();

    // Bob loses his state for Alice (e.g. restored an old backup).
    let alice_dev = bob.trust_device_of(&alice).unwrap();
    bob.device.drop_sessions(&alice_dev);
    let env = send(&mut alice, &mut bob, "lost");
    assert!(receive(&mut bob, &alice, &env).is_err());

    // Alice is told (RetryRequest) and starts over from a new prekey.
    let bob_dev = alice.trust_device_of(&bob).unwrap();
    alice.device.drop_sessions(&bob_dev);
    let env = send(&mut alice, &mut bob, "lost (resent)");
    assert_eq!(text_of(&receive(&mut bob, &alice, &env).unwrap()), "lost (resent)");
}

#[test]
fn envelope_sizes_only_take_bucket_values() {
    let mut alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let mut sizes = std::collections::BTreeSet::new();
    for len in [0usize, 1, 10, 100, 300, 1000, 5000] {
        let env = send(&mut alice, &mut bob, &"x".repeat(len));
        sizes.insert(env.len());
        receive(&mut bob, &alice, &env).unwrap();
    }
    // Seven very different lengths collapse into at most three sizes.
    assert!(sizes.len() <= 3, "{sizes:?}");
}

#[test]
fn oversized_messages_are_refused() {
    let mut alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let to = alice.trust_device_of(&bob).unwrap();
    let pk = bob.claim_prekey();
    let r = alice.device.encrypt(&to, Some(&pk), &text(&"x".repeat(70_000)));
    assert_eq!(r, Err(CoreError::TooLarge));
}

#[test]
fn an_unregistered_device_cannot_send() {
    let master = MasterKey::generate();
    let mut d = LocalDevice::new(9, km_core::DeviceKind::Web);
    assert_eq!(d.publish_prekeys(1, false), Err(CoreError::Unregistered));
    d.set_device_id(5).unwrap();
    assert_eq!(d.set_device_id(6), Err(CoreError::AlreadyRegistered));
    master.certify(&d.keys()).verify(&master.public_key()).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Any delivery order, with any messages lost: every delivered message
    /// decrypts exactly once and nothing else does.
    #[test]
    fn out_of_order_and_lossy_delivery(
        count in 1usize..40,
        order in proptest::collection::vec(any::<u32>(), 40),
        drop in proptest::collection::vec(any::<bool>(), 40),
    ) {
        let mut alice = Person::new(1, 101);
        let mut bob = Person::new(2, 202);
        let mut envs: Vec<(usize, Vec<u8>)> =
            (0..count).map(|i| (i, send(&mut alice, &mut bob, &format!("m{i}")))).collect();
        // Shuffle by the random keys, then drop some (always keep at least one).
        envs.sort_by_key(|(i, _)| order[*i]);
        let kept: Vec<_> = envs.iter().enumerate()
            .filter(|(pos, (i, _))| *pos == 0 || !drop[*i])
            .map(|(_, e)| e.clone()).collect();
        for (i, env) in &kept {
            let got = receive(&mut bob, &alice, env).unwrap();
            prop_assert_eq!(text_of(&got), format!("m{i}"));
        }
        // Redelivering everything again yields nothing new.
        for (_, env) in &kept {
            prop_assert!(receive(&mut bob, &alice, env).is_err());
        }
    }

    /// Both sides talking at once, interleaved arbitrarily, stays in sync.
    #[test]
    fn interleaved_two_way_traffic(turns in proptest::collection::vec(any::<bool>(), 1..60)) {
        let mut alice = Person::new(1, 101);
        let mut bob = Person::new(2, 202);
        // Establish first so both directions have a session.
        let env = send(&mut alice, &mut bob, "hello");
        receive(&mut bob, &alice, &env).unwrap();
        for (n, alice_speaks) in turns.into_iter().enumerate() {
            let msg = format!("t{n}");
            if alice_speaks {
                let env = send(&mut alice, &mut bob, &msg);
                let got = receive(&mut bob, &alice, &env).unwrap();
                prop_assert_eq!(text_of(&got), msg);
            } else {
                let env = send(&mut bob, &mut alice, &msg);
                let got = receive(&mut alice, &bob, &env).unwrap();
                prop_assert_eq!(text_of(&got), msg);
            }
        }
    }

    /// Flipping any single byte of an envelope never produces a plaintext.
    #[test]
    fn any_bit_flip_is_rejected(pos in any::<prop::sample::Index>(), bit in 0u8..8) {
        let mut alice = Person::new(1, 101);
        let mut bob = Person::new(2, 202);
        let mut env = send(&mut alice, &mut bob, "integrity");
        let i = pos.index(env.len());
        env[i] ^= 1 << bit;
        prop_assert!(receive(&mut bob, &alice, &env).is_err());
    }
}
