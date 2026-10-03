//! The core flows again, run inside a WebAssembly runtime (Node), where the
//! web client will run them: random numbers come from crypto.getRandomValues
//! and nothing may touch the OS.
//!
//!   cargo test -p km-core --target wasm32-unknown-unknown --test wasm
//!
//! (runner: wasm-bindgen-test-runner, set in .cargo/config.toml)
#![cfg(target_arch = "wasm32")]

mod common;

use common::*;
use km_core::{safety_number, CoreError, LocalDevice, MasterKey};
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
fn conversation_both_ways() {
    let mut alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let env = send(&mut alice, &mut bob, "hi from wasm");
    assert_eq!(text_of(&receive(&mut bob, &alice, &env).unwrap()), "hi from wasm");
    for i in 0..20 {
        let env = send(&mut bob, &mut alice, &format!("r{i}"));
        assert_eq!(text_of(&receive(&mut alice, &bob, &env).unwrap()), format!("r{i}"));
    }
}

#[wasm_bindgen_test]
fn out_of_order_and_replay() {
    let mut alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let envs: Vec<_> = (0..10).map(|i| send(&mut alice, &mut bob, &format!("m{i}"))).collect();
    for i in [3usize, 0, 9, 1, 2, 8, 4, 7, 5, 6] {
        assert_eq!(text_of(&receive(&mut bob, &alice, &envs[i]).unwrap()), format!("m{i}"));
    }
    assert!(receive(&mut bob, &alice, &envs[4]).is_err());
}

#[wasm_bindgen_test]
fn forged_sender_and_key_change() {
    let alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let mut mallory = Person::new(1, 101);
    let to = mallory.trust_device_of(&bob).unwrap();
    let pk = bob.claim_prekey();
    let env = mallory.device.encrypt(&to, Some(&pk), &text("i am alice")).unwrap();
    assert_eq!(receive(&mut bob, &alice, &env), Err(CoreError::Undecryptable));

    let mut carol = Person::new(3, 303);
    carol.trust_device_of(&bob).unwrap();
    bob.master = MasterKey::generate();
    bob.signed = bob.master.certify(&bob.device.keys());
    assert_eq!(carol.trust_device_of(&bob).unwrap_err(), CoreError::IdentityChanged { user_id: 2 });
}

#[wasm_bindgen_test]
fn snapshot_restore_and_golden_safety_number() {
    let mut alice = Person::new(1, 101);
    let mut bob = Person::new(2, 202);
    let env = send(&mut alice, &mut bob, "a");
    receive(&mut bob, &alice, &env).unwrap();
    bob.device = LocalDevice::restore(&bob.device.snapshot().unwrap()).unwrap();
    let env = send(&mut bob, &mut alice, "b");
    assert_eq!(text_of(&receive(&mut alice, &bob, &env).unwrap()), "b");
    // Same number natively and in the browser.
    assert_eq!(safety_number(1, &[1; 32], 2, &[2; 32]), include_str!("golden_safety_number.txt"));
}
