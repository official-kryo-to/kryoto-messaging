//! Which master key belongs to which user, and which devices to believe.
//!
//! Trust on first use, then pinned. The server can hand a client any key it
//! likes; the client accepts the first one it sees for a user and from then on
//! refuses to use a different one until the person explicitly acknowledges the
//! change (the loud warning in the UI). Verifying a safety number marks the pin
//! as verified; a change always clears that.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::keys::{DeviceKeys, SignedDevice};

/// A user's master key and device list, as fetched from the directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserDevices {
    pub user_id: u64,
    pub master_key: [u8; 32],
    pub devices: Vec<SignedDevice>,
}

/// A device that passed every check: its certificate verifies against the
/// user's pinned master key. Only the trust store makes these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedDevice {
    keys: DeviceKeys,
}

impl TrustedDevice {
    pub fn keys(&self) -> &DeviceKeys {
        &self.keys
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Pinned on first use, never compared in person.
    Unverified,
    /// Safety number or QR code confirmed.
    Verified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Pin {
    master_key: [u8; 32],
    level: TrustLevel,
    /// A different key the directory has offered and the person has not yet
    /// acknowledged. While set, nothing is sent to this user.
    pending_change: Option<[u8; 32]>,
}

/// Result of checking a fetched device list.
#[derive(Debug)]
pub struct CheckedDevices {
    pub devices: Vec<TrustedDevice>,
    /// Devices whose certificate did not verify. They are left out; a non-zero
    /// count is worth surfacing (it means the directory is serving garbage).
    pub rejected: usize,
    pub first_use: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrustStore {
    pins: HashMap<u64, Pin>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin our own master key. Our own devices are checked like anybody's.
    pub fn pin_own(&mut self, user_id: u64, master_key: [u8; 32]) {
        self.pins.insert(user_id, Pin { master_key, level: TrustLevel::Verified, pending_change: None });
    }

    /// Check a device list against the pin, pinning it if this is the first
    /// time we see this user.
    pub fn check(&mut self, fetched: &UserDevices) -> Result<CheckedDevices> {
        let first_use = match self.pins.get_mut(&fetched.user_id) {
            None => {
                self.pins.insert(
                    fetched.user_id,
                    Pin { master_key: fetched.master_key, level: TrustLevel::Unverified, pending_change: None },
                );
                true
            }
            Some(pin) if pin.master_key == fetched.master_key => {
                // The directory went back to the key we know: nothing to acknowledge.
                pin.pending_change = None;
                false
            }
            Some(pin) => {
                pin.pending_change = Some(fetched.master_key);
                return Err(CoreError::IdentityChanged { user_id: fetched.user_id });
            }
        };

        let mut devices = Vec::with_capacity(fetched.devices.len());
        let mut rejected = 0;
        for d in &fetched.devices {
            let belongs = d.keys.user_id == fetched.user_id;
            if belongs && d.verify(&fetched.master_key).is_ok() {
                devices.push(TrustedDevice { keys: d.keys.clone() });
            } else {
                rejected += 1;
            }
        }
        Ok(CheckedDevices { devices, rejected, first_use })
    }

    /// The person saw the warning and chose to accept the new key. Clears
    /// verification: the new key has to be verified again.
    pub fn acknowledge_change(&mut self, user_id: u64) -> Result<()> {
        let pin = self.pins.get_mut(&user_id).ok_or(CoreError::UnknownIdentity { user_id })?;
        let new_key = pin.pending_change.take().ok_or(CoreError::UnknownIdentity { user_id })?;
        pin.master_key = new_key;
        pin.level = TrustLevel::Unverified;
        Ok(())
    }

    /// Mark a user verified, but only if the key compared in person is the
    /// one we have pinned.
    pub fn mark_verified(&mut self, user_id: u64, master_key: &[u8; 32]) -> Result<()> {
        let pin = self.pins.get_mut(&user_id).ok_or(CoreError::UnknownIdentity { user_id })?;
        if pin.pending_change.is_some() {
            return Err(CoreError::IdentityChanged { user_id });
        }
        if &pin.master_key != master_key {
            return Err(CoreError::BadKey);
        }
        pin.level = TrustLevel::Verified;
        Ok(())
    }

    /// Take back "verified" (the person is no longer sure).
    pub fn mark_unverified(&mut self, user_id: u64) -> Result<()> {
        let pin = self.pins.get_mut(&user_id).ok_or(CoreError::UnknownIdentity { user_id })?;
        pin.level = TrustLevel::Unverified;
        Ok(())
    }

    pub fn pinned(&self, user_id: u64) -> Option<([u8; 32], TrustLevel)> {
        self.pins.get(&user_id).map(|p| (p.master_key, p.level))
    }

    pub fn has_pending_change(&self, user_id: u64) -> bool {
        self.pins.get(&user_id).is_some_and(|p| p.pending_change.is_some())
    }
}
