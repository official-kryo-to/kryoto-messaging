#![allow(dead_code)]

use km_core::proto::{content::Body, Content, Text};
use km_core::{
    new_message_id, DeviceKind, Inbound, LocalDevice, MasterKey, Result, SignedDevice, SignedPrekey, TrustStore,
    TrustedDevice, UserDevices,
};

/// One person with one registered device, a master key and a trust store.
pub struct Person {
    pub user_id: u64,
    pub master: MasterKey,
    pub device: LocalDevice,
    pub signed: SignedDevice,
    pub trust: TrustStore,
    /// What this device has uploaded and the server still holds.
    pub prekeys: Vec<SignedPrekey>,
}

impl Person {
    pub fn new(user_id: u64, device_id: u64) -> Self {
        let master = MasterKey::generate();
        let mut device = LocalDevice::new(user_id, DeviceKind::Desktop);
        device.set_device_id(device_id).unwrap();
        let signed = master.certify(&device.keys());
        let prekeys = device.publish_prekeys(20, true).unwrap();
        let mut trust = TrustStore::new();
        trust.pin_own(user_id, master.public_key());
        Self { user_id, master, device, signed, trust, prekeys }
    }

    pub fn directory_entry(&self) -> UserDevices {
        UserDevices { user_id: self.user_id, master_key: self.master.public_key(), devices: vec![self.signed.clone()] }
    }

    /// The server's /keys/claim: pop one one-time key, else the fallback.
    pub fn claim_prekey(&mut self) -> SignedPrekey {
        if let Some(pos) = self.prekeys.iter().position(|p| !p.fallback) {
            self.prekeys.remove(pos)
        } else {
            self.prekeys.iter().find(|p| p.fallback).cloned().expect("a fallback key")
        }
    }

    /// Fetch and check someone's single device through our trust store.
    pub fn trust_device_of(&mut self, other: &Person) -> Result<TrustedDevice> {
        let checked = self.trust.check(&other.directory_entry())?;
        Ok(checked.devices.into_iter().next().expect("one device"))
    }
}

pub fn text(s: &str) -> Content {
    Content {
        msg_id: new_message_id().to_vec(),
        conversation_id: b"conv".to_vec(),
        sent_at_ms: 1_700_000_000_000,
        body: Some(Body::Text(Text { text: s.into(), reply_to: vec![] })),
    }
}

pub fn text_of(inbound: &Inbound) -> &str {
    match &inbound.content.body {
        Some(Body::Text(t)) => &t.text,
        _ => panic!("not a text message"),
    }
}

/// A sends `msg` to B, starting a session from a claimed prekey if needed.
pub fn send(a: &mut Person, b: &mut Person, msg: &str) -> Vec<u8> {
    let to = a.trust_device_of(b).unwrap();
    let prekey = if a.device.has_session(&to) { None } else { Some(b.claim_prekey()) };
    a.device.encrypt(&to, prekey.as_ref(), &text(msg)).unwrap()
}

/// B decrypts an envelope from A.
pub fn receive(b: &mut Person, a: &Person, envelope: &[u8]) -> Result<Inbound> {
    let sender = b.trust_device_of(a)?;
    b.device.decrypt(envelope, |u, d| (u == sender.keys().user_id && d == sender.keys().device_id).then(|| sender.clone()))
}
