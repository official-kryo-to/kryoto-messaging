mod common;

use common::*;
use km_core::{display_groups, qr_payload, safety_number, verify_qr, CoreError, MasterKey, TrustLevel, TrustStore};

#[test]
fn first_use_pins_and_the_same_key_passes() {
    let bob = Person::new(2, 202);
    let mut trust = TrustStore::new();
    let first = trust.check(&bob.directory_entry()).unwrap();
    assert!(first.first_use);
    assert_eq!(first.devices.len(), 1);
    assert_eq!(first.rejected, 0);
    let again = trust.check(&bob.directory_entry()).unwrap();
    assert!(!again.first_use);
    assert_eq!(trust.pinned(2).unwrap().1, TrustLevel::Unverified);
}

#[test]
fn a_changed_master_key_blocks_until_acknowledged_and_drops_verification() {
    let mut bob = Person::new(2, 202);
    let mut trust = TrustStore::new();
    trust.check(&bob.directory_entry()).unwrap();
    trust.mark_verified(2, &bob.master.public_key()).unwrap();

    // Bob (or an attacker holding the server) now presents a different key.
    bob.master = MasterKey::generate();
    bob.signed = bob.master.certify(&bob.device.keys());
    assert_eq!(trust.check(&bob.directory_entry()).unwrap_err(), CoreError::IdentityChanged { user_id: 2 });
    assert!(trust.has_pending_change(2));
    // Still blocked on every retry.
    assert!(trust.check(&bob.directory_entry()).is_err());
    // Cannot verify the new key without acknowledging first.
    assert!(trust.mark_verified(2, &bob.master.public_key()).is_err());

    trust.acknowledge_change(2).unwrap();
    let checked = trust.check(&bob.directory_entry()).unwrap();
    assert_eq!(checked.devices.len(), 1);
    assert_eq!(trust.pinned(2).unwrap().1, TrustLevel::Unverified, "verification must be lost");
}

#[test]
fn messages_stop_when_the_key_changes() {
    let mut alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let env = send(&mut alice, &mut bob, "before");
    receive(&mut bob, &alice, &env).unwrap();
    bob.master = MasterKey::generate();
    bob.signed = bob.master.certify(&bob.device.keys());
    assert_eq!(alice.trust_device_of(&bob).unwrap_err(), CoreError::IdentityChanged { user_id: 2 });
}

#[test]
fn devices_with_bad_certificates_are_left_out() {
    let bob = Person::new(2, 202);
    let mut entry = bob.directory_entry();
    // A device signed by some other master key, and one claiming another user.
    let rogue_master = MasterKey::generate();
    let mut forged = rogue_master.certify(&bob.device.keys());
    forged.keys.device_id = 999;
    entry.devices.push(forged);
    let mut wrong_user = bob.signed.clone();
    wrong_user.keys.user_id = 3;
    entry.devices.push(wrong_user);
    let mut tampered = bob.signed.clone();
    tampered.keys.seal_key[0] ^= 1;
    entry.devices.push(tampered);

    let checked = TrustStore::new().check(&entry).unwrap();
    assert_eq!(checked.devices.len(), 1);
    assert_eq!(checked.rejected, 3);
}

#[test]
fn verifying_a_key_that_is_not_pinned_fails() {
    let bob = Person::new(2, 202);
    let mut trust = TrustStore::new();
    assert!(trust.mark_verified(2, &bob.master.public_key()).is_err());
    trust.check(&bob.directory_entry()).unwrap();
    assert_eq!(trust.mark_verified(2, &MasterKey::generate().public_key()), Err(CoreError::BadKey));
}

#[test]
fn safety_numbers_match_on_both_sides_and_change_with_the_key() {
    let a = MasterKey::generate().public_key();
    let b = MasterKey::generate().public_key();
    let ab = safety_number(1, &a, 2, &b);
    let ba = safety_number(2, &b, 1, &a);
    assert_eq!(ab, ba);
    assert_eq!(ab.len(), 60);
    assert!(ab.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(display_groups(&ab).len(), 12);

    let c = MasterKey::generate().public_key();
    assert_ne!(safety_number(1, &a, 2, &c), ab);
    // The user id is part of it: same key under another account differs.
    assert_ne!(safety_number(1, &a, 3, &b), ab);
}

#[test]
fn safety_number_is_stable_across_versions() {
    // Golden value: if this changes, every user's safety number changed.
    let a = [1u8; 32];
    let b = [2u8; 32];
    let n = safety_number(1, &a, 2, &b);
    assert_eq!(n, GOLDEN, "safety number format changed");
}
const GOLDEN: &str = include_str!("golden_safety_number.txt");

#[test]
fn qr_verification_both_ways() {
    let a = MasterKey::generate().public_key();
    let b = MasterKey::generate().public_key();
    // Bob shows his code; Alice scans it.
    let bobs_code = qr_payload(2, &b, 1, &a);
    assert!(verify_qr(&bobs_code, 1, &a, 2, &b).unwrap());
    // Alice holds a wrong key for Bob (MITM): no match.
    let mitm = MasterKey::generate().public_key();
    assert!(!verify_qr(&bobs_code, 1, &a, 2, &mitm).unwrap());
    // Garbage is an error, not a match.
    assert!(verify_qr(&bobs_code[..10], 1, &a, 2, &b).is_err());
}

#[test]
fn gateway_proofs_bind_nonce_account_and_device() {
    let p = Person::new(7, 70);
    let nonce = [3u8; 32];
    let sig = p.device.sign_gateway_challenge(&nonce, 70);
    let ed = p.device.keys().ed25519;
    km_core::verify_gateway_proof(&ed, &nonce, 7, 70, &sig).unwrap();
    assert!(km_core::verify_gateway_proof(&ed, &[4u8; 32], 7, 70, &sig).is_err(), "other nonce");
    assert!(km_core::verify_gateway_proof(&ed, &nonce, 8, 70, &sig).is_err(), "other account");
    assert!(km_core::verify_gateway_proof(&ed, &nonce, 7, 71, &sig).is_err(), "other device");
}
