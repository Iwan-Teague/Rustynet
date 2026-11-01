//! Key custody for `control.db` at-rest sealing (AQ-45 step 2).
//!
//! Implements §4 of `charter/design/rustynet-control-db-atrest-v0.2.md`:
//! the 32-byte value-encryption DEK lives in the OS
//! secure store — never in the database file, a config file, or a
//! passphrase. The keystore item id is [`CONTROL_DB_DEK_VALUE_ITEM_ID`];
//! this flattened id is the permanent
//! id the vault will adopt (the design's slash-separated name is not
//! a valid keystore identifier, and renaming after first use would orphan the
//! stored DEK). The keystore is pinned to
//! `RequireOsSecureStore` semantics (no encrypted-file fallback), which is
//! provisional on OI-46 Q3.
//!
//! The minting rule is fail-closed: a fresh key is drawn **only** after the
//! store has *proved* the item absent; a store that cannot answer whether
//! the item exists never triggers minting, never overwrites, and never
//! produces a key. Provisioning is create-only, and the minted key is
//! adopted only after a read-back comparison.

use std::fmt;

use rand::TryRngCore;
use rand::rngs::OsRng;
use rustynet_crypto::{OsSecureStore, OsStoreLookup, PlatformOsSecureStore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Keystore item for the value-column DEK (design §4 names it
/// `rustynet/control-db/dek/value/v1`).
///
/// DESIGN DEVIATION (documented in the AQ-45 step-2 report): the design's
/// slash-separated name is not a valid `rustynet-crypto` key identifier
/// (`is_valid_key_identifier` allows ASCII alphanumerics, `-` and `_` only),
/// so it is flattened to `control-db-dek-value-v1`. The flattened id is the
/// permanent keystore name: the vault adopts it as-is, and renaming after
/// first use would orphan the stored DEK (no re-encryption path).
pub const CONTROL_DB_DEK_VALUE_ITEM_ID: &str = "control-db-dek-value-v1";

/// Why a control-database DEK could not be produced.
///
/// The two variants are exhaustive on purpose and carry no payload: the
/// distinction a caller must act on is exactly "the store proved the item
/// does not exist" versus "the store could not answer". Neither message
/// quotes store internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DbKeyError {
    /// The store positively proved that the keystore item does not exist.
    /// This is the only state under which [`load_or_provision`] may mint a
    /// fresh key.
    Absent,
    /// The store could not answer: backend failure, transport error, a load
    /// mechanism that failed for a non-absence reason, an item of the wrong
    /// length, or a failed/unverified provision. Never provision, never
    /// overwrite, never return a key.
    Unavailable,
}

impl fmt::Display for DbKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbKeyError::Absent => f.write_str("control database key item is not present"),
            DbKeyError::Unavailable => f.write_str("control database key store could not answer"),
        }
    }
}

impl std::error::Error for DbKeyError {}

/// Source of the 32-byte control-database DEKs (design §4).
///
/// Implementors wrap a keystore (the shipping implementation talks to the OS
/// secure store via `rustynet_crypto::OsSecureStore`). The contract:
///
/// - [`ControlDbKeySource::load`] returns the stored key, [`DbKeyError::Absent`]
///   only when the store *proved* the item absent, and [`DbKeyError::Unavailable`]
///   whenever it could not answer.
/// - [`ControlDbKeySource::provision`] stores a newly drawn key
///   create-only: if an item already exists it must refuse, leaving the
///   existing item byte-for-byte unchanged.
pub trait ControlDbKeySource: Send + Sync {
    /// Load the DEK for this source's keystore item.
    fn load(&self) -> Result<Zeroizing<[u8; 32]>, DbKeyError>;

    /// Store `key` under this source's keystore item, refusing to overwrite
    /// any existing item.
    fn provision(&self, key: &Zeroizing<[u8; 32]>) -> Result<(), DbKeyError>;
}

/// Load the DEK, minting a fresh one only when the store has proved the item
/// absent (design §4 "load-or-provision").
///
/// # REQUIREMENT — callers must serialize first provisioning
///
/// First provisioning for one database MUST be serialized across processes
/// (the step 5/6 open path satisfies this by provisioning only while holding
/// the control.db write lock, `BEGIN IMMEDIATE`; the lock itself is NOT
/// implemented in step 2 — it is a hand-off to steps 5/6). Without
/// serialization the Linux upsert store can give two concurrent
/// first-provisioners two different ADOPTED keys: both probe `Absent`, A
/// stores KA and its read-back self-matches, B then overwrites with KB and
/// its read-back also self-matches — both succeed, one side's sealed writes
/// are orphaned, and the divergence only surfaces at the NEXT open as a
/// fail-closed mismatch (see `store_in_linux_secret_service_create_only`).
/// Serialization makes the create-only probe-then-store window single-writer
/// so that interleaving cannot occur.
///
/// Discipline:
///
/// - `Ok(key)` — the stored key, returned as-is.
/// - `Err(Unavailable)` — returned untouched; `provision` is never called.
///   A store that cannot answer must never be "fixed" by re-keying.
/// - `Err(Absent)` — draw 32 fresh bytes from the kernel CSPRNG (`OsRng`;
///   an entropy failure is `Unavailable`, with no `ThreadRng` fallback),
///   `provision` it, then **load back and constant-time compare**: the key
///   is adopted only if the store returns exactly what was drawn. A provision
///   failure, a failed read-back, or a mismatch is `Unavailable` and nothing
///   is adopted — this is what converts a create-only refusal race into a
///   safe refusal rather than a split-brain key. (On Linux the read-back
///   compare alone does NOT serialize provisioners — see the REQUIREMENT
///   above.)
pub fn load_or_provision(
    source: &dyn ControlDbKeySource,
) -> Result<Zeroizing<[u8; 32]>, DbKeyError> {
    match source.load() {
        Ok(key) => return Ok(key),
        Err(DbKeyError::Unavailable) => return Err(DbKeyError::Unavailable),
        Err(DbKeyError::Absent) => {}
    }

    let mut key = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(key.as_mut_slice())
        .map_err(|_| DbKeyError::Unavailable)?;
    source.provision(&key)?;

    let loaded = source.load()?;
    if (*loaded).ct_eq(&*key).into() {
        Ok(loaded)
    } else {
        Err(DbKeyError::Unavailable)
    }
}

/// [`ControlDbKeySource`] backed by an `OsSecureStore` item (design §4).
///
/// Provisional on OI-46 Q3: this adapter talks ONLY to the OS secure store —
/// it never consults `KeyCustodyManager`'s encrypted-file fallback and never
/// creates one, so on a host without a working OS store the DEK is
/// `Unavailable`, fail-closed.
///
/// The generic default is [`PlatformOsSecureStore`]; tests substitute a fake
/// store. The `Default`-method semantics of `OsSecureStore` are load-bearing:
/// a store whose `lookup_key` cannot prove absence yields `Unavailable`, so
/// a plain `store_key`/`load_key` implementor can never trigger minting.
pub struct OsSecureStoreControlDbKeySource<S: OsSecureStore = PlatformOsSecureStore> {
    store: S,
    item_id: &'static str,
}

impl<S: OsSecureStore> OsSecureStoreControlDbKeySource<S> {
    /// Wrap `store` for keystore item `item_id`.
    pub const fn new(store: S, item_id: &'static str) -> Self {
        Self { store, item_id }
    }

    /// Source for [`CONTROL_DB_DEK_VALUE_ITEM_ID`] (the value-column DEK).
    pub const fn value_dek(store: S) -> Self {
        Self::new(store, CONTROL_DB_DEK_VALUE_ITEM_ID)
    }
}

impl<S: OsSecureStore> fmt::Debug for OsSecureStoreControlDbKeySource<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The store may hold key material; it is never rendered.
        f.debug_struct("OsSecureStoreControlDbKeySource")
            .field("store", &"..")
            .field("item_id", &self.item_id)
            .finish()
    }
}

impl<S: OsSecureStore + Send + Sync> ControlDbKeySource for OsSecureStoreControlDbKeySource<S> {
    fn load(&self) -> Result<Zeroizing<[u8; 32]>, DbKeyError> {
        match self.store.lookup_key(self.item_id) {
            OsStoreLookup::Found(payload) => {
                let key: [u8; 32] = <[u8; 32]>::try_from(payload.as_slice())
                    .map_err(|_| DbKeyError::Unavailable)?;
                Ok(Zeroizing::new(key))
            }
            // Wrong length is a store problem, not an absence proof: the item
            // EXISTS but is not a usable DEK. Minting over it would destroy
            // the only copy of the sealed-database key.
            OsStoreLookup::ProvedAbsent => Err(DbKeyError::Absent),
            OsStoreLookup::Unavailable => Err(DbKeyError::Unavailable),
        }
    }

    fn provision(&self, key: &Zeroizing<[u8; 32]>) -> Result<(), DbKeyError> {
        self.store
            .store_key_create_only(self.item_id, &**key)
            .map_err(|_| DbKeyError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const ITEM: &str = "control-db-dek-value-v1";

    /// In-memory [`ControlDbKeySource`] with call counters and failure
    /// switches. Never touches a real keystore.
    struct MemoryState {
        items: HashMap<String, [u8; 32]>,
        load_calls: u32,
        provision_calls: u32,
        always_unavailable: bool,
        provision_fails: bool,
        provision_corrupts: bool,
    }

    struct CountingMemoryStore {
        item_id: &'static str,
        state: Mutex<MemoryState>,
    }

    impl CountingMemoryStore {
        fn new() -> Self {
            Self {
                item_id: ITEM,
                state: Mutex::new(MemoryState {
                    items: HashMap::new(),
                    load_calls: 0,
                    provision_calls: 0,
                    always_unavailable: false,
                    provision_fails: false,
                    provision_corrupts: false,
                }),
            }
        }

        fn with_always_unavailable() -> Self {
            let store = Self::new();
            store.state.lock().unwrap().always_unavailable = true;
            store
        }

        fn with_provision_fails() -> Self {
            let store = Self::new();
            store.state.lock().unwrap().provision_fails = true;
            store
        }

        fn with_provision_corrupts() -> Self {
            let store = Self::new();
            store.state.lock().unwrap().provision_corrupts = true;
            store
        }
    }

    impl ControlDbKeySource for CountingMemoryStore {
        fn load(&self) -> Result<Zeroizing<[u8; 32]>, DbKeyError> {
            let mut state = self.state.lock().unwrap();
            state.load_calls += 1;
            if state.always_unavailable {
                return Err(DbKeyError::Unavailable);
            }
            match state.items.get(self.item_id) {
                Some(key) => Ok(Zeroizing::new(*key)),
                None => Err(DbKeyError::Absent),
            }
        }

        fn provision(&self, key: &Zeroizing<[u8; 32]>) -> Result<(), DbKeyError> {
            let mut state = self.state.lock().unwrap();
            state.provision_calls += 1;
            if state.provision_fails {
                return Err(DbKeyError::Unavailable);
            }
            let mut stored: [u8; 32] = **key;
            if state.provision_corrupts {
                stored[0] ^= 0xFF;
            }
            state.items.insert(self.item_id.to_string(), stored);
            Ok(())
        }
    }

    #[test]
    fn unavailable_store_never_mints_silently() {
        let store = CountingMemoryStore::with_always_unavailable();
        for _ in 0..50 {
            assert_eq!(load_or_provision(&store), Err(DbKeyError::Unavailable));
        }
        let state = store.state.lock().unwrap();
        assert_eq!(state.provision_calls, 0);
        assert_eq!(state.load_calls, 50);
        assert!(state.items.is_empty());
    }

    #[test]
    fn absent_store_provisions_exactly_once_then_loads() {
        let store = CountingMemoryStore::new();
        let first = load_or_provision(&store).unwrap();
        assert_eq!(first, load_or_provision(&store).unwrap());
        let state = store.state.lock().unwrap();
        assert_eq!(state.provision_calls, 1);
        assert_eq!(state.items.len(), 1);
        assert_eq!(state.items.get(ITEM), Some(&*first));
    }

    #[test]
    fn two_fresh_stores_draw_different_keys() {
        let a = load_or_provision(&CountingMemoryStore::new()).unwrap();
        let b = load_or_provision(&CountingMemoryStore::new()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn provision_failure_is_unavailable_and_stores_nothing() {
        let store = CountingMemoryStore::with_provision_fails();
        assert_eq!(load_or_provision(&store), Err(DbKeyError::Unavailable));
        let state = store.state.lock().unwrap();
        assert_eq!(state.provision_calls, 1);
        assert!(state.items.is_empty());
    }

    #[test]
    fn load_back_mismatch_is_unavailable_and_adopts_nothing() {
        let store = CountingMemoryStore::with_provision_corrupts();
        assert_eq!(load_or_provision(&store), Err(DbKeyError::Unavailable));
        let state = store.state.lock().unwrap();
        assert_eq!(state.provision_calls, 1);
        assert_eq!(state.items.len(), 1);
    }

    #[test]
    fn db_key_error_display_and_debug_leak_nothing() {
        assert_eq!(
            DbKeyError::Absent.to_string(),
            "control database key item is not present"
        );
        assert_eq!(
            DbKeyError::Unavailable.to_string(),
            "control database key store could not answer"
        );
        // Derived Debug carries only the variant names, no payload.
        assert_eq!(format!("{:?}", DbKeyError::Absent), "Absent");
        assert_eq!(format!("{:?}", DbKeyError::Unavailable), "Unavailable");
    }

    #[test]
    fn source_debug_redacts_store() {
        let source = OsSecureStoreControlDbKeySource::value_dek(FakeOsStore::new());
        let rendered = format!("{source:?}");
        assert!(rendered.contains("item_id"), "rendered: {rendered}");
        assert!(!rendered.contains("MemoryState"), "rendered: {rendered}");
        assert!(!rendered.contains("items"), "rendered: {rendered}");
    }

    /// Fake OS store for the adapter: counters plus a switch that forces the
    /// lookup answer to `ProvedAbsent` regardless of stored items.
    struct FakeOsState {
        items: HashMap<String, Vec<u8>>,
        lookup_calls: u32,
        create_calls: u32,
        force_proved_absent: bool,
    }

    struct FakeOsStore {
        state: Mutex<FakeOsState>,
    }

    impl FakeOsStore {
        fn new() -> Self {
            Self {
                state: Mutex::new(FakeOsState {
                    items: HashMap::new(),
                    lookup_calls: 0,
                    create_calls: 0,
                    force_proved_absent: false,
                }),
            }
        }

        fn with_preseeded(payload: &[u8]) -> Self {
            let store = Self::new();
            store
                .state
                .lock()
                .unwrap()
                .items
                .insert(ITEM.to_string(), payload.to_vec());
            store
        }
    }

    impl OsSecureStore for FakeOsStore {
        fn store_key(
            &self,
            key_id: &str,
            key_material: &[u8],
        ) -> Result<(), rustynet_crypto::CryptoError> {
            self.state
                .lock()
                .unwrap()
                .items
                .insert(key_id.to_string(), key_material.to_vec());
            Ok(())
        }

        fn load_key(
            &self,
            key_id: &str,
        ) -> Result<Zeroizing<Vec<u8>>, rustynet_crypto::CryptoError> {
            match self.state.lock().unwrap().items.get(key_id) {
                Some(bytes) => Ok(Zeroizing::new(bytes.clone())),
                None => Err(rustynet_crypto::CryptoError::OsStoreUnavailable),
            }
        }

        fn lookup_key(&self, key_id: &str) -> OsStoreLookup {
            let mut state = self.state.lock().unwrap();
            state.lookup_calls += 1;
            if state.force_proved_absent {
                return OsStoreLookup::ProvedAbsent;
            }
            match state.items.get(key_id) {
                Some(bytes) => OsStoreLookup::Found(Zeroizing::new(bytes.clone())),
                None => OsStoreLookup::ProvedAbsent,
            }
        }

        fn store_key_create_only(
            &self,
            key_id: &str,
            key_material: &[u8],
        ) -> Result<(), rustynet_crypto::CryptoError> {
            let mut state = self.state.lock().unwrap();
            state.create_calls += 1;
            if state.items.contains_key(key_id) {
                // Create-only refusal: existing item stays byte-for-byte.
                return Err(rustynet_crypto::CryptoError::OsStoreUnavailable);
            }
            state
                .items
                .insert(key_id.to_string(), key_material.to_vec());
            Ok(())
        }
    }

    #[test]
    fn adapter_maps_lookup_answers_to_db_key_errors() {
        let store = FakeOsStore::new();
        let source = OsSecureStoreControlDbKeySource::value_dek(store);
        assert_eq!(source.load(), Err(DbKeyError::Absent));
        source.provision(&Zeroizing::new([9u8; 32])).unwrap();
        assert_eq!(source.load().unwrap(), Zeroizing::new([9u8; 32]));
    }

    #[test]
    fn create_only_refusal_leaves_existing_item_untouched() {
        let original = [7u8; 32];
        let store = FakeOsStore::with_preseeded(&original);
        store.state.lock().unwrap().force_proved_absent = true;
        let source = OsSecureStoreControlDbKeySource::value_dek(store);
        // Even if a lookup wrongly (or later race-ily) reports Absent, the
        // create-only provision must refuse and the existing item must
        // survive unchanged.
        assert_eq!(source.load(), Err(DbKeyError::Absent));
        let fresh = Zeroizing::new([1u8; 32]);
        assert_eq!(source.provision(&fresh), Err(DbKeyError::Unavailable));
        let state = source.store.state.lock().unwrap();
        assert_eq!(state.create_calls, 1);
        assert_eq!(state.items.get(ITEM), Some(&original.to_vec()));
    }

    #[test]
    fn wrong_length_found_item_is_unavailable_never_absent() {
        let store = FakeOsStore::new();
        store
            .state
            .lock()
            .unwrap()
            .items
            .insert(ITEM.to_string(), vec![0xABu8; 31]);
        let source = OsSecureStoreControlDbKeySource::value_dek(store);
        assert_eq!(source.load(), Err(DbKeyError::Unavailable));
        assert_eq!(source.store.state.lock().unwrap().create_calls, 0);
    }

    #[test]
    fn default_trait_methods_keep_conservative_semantics_through_adapter() {
        // A store implementing only store_key/load_key: default lookup_key
        // never reports ProvedAbsent (so load is Unavailable, never Absent)
        // and default store_key_create_only refuses, so load_or_provision
        // can neither mint nor store through it.
        struct BareStore;
        impl OsSecureStore for BareStore {
            fn store_key(
                &self,
                _key_id: &str,
                _key_material: &[u8],
            ) -> Result<(), rustynet_crypto::CryptoError> {
                Err(rustynet_crypto::CryptoError::OsStoreUnavailable)
            }
            fn load_key(
                &self,
                _key_id: &str,
            ) -> Result<Zeroizing<Vec<u8>>, rustynet_crypto::CryptoError> {
                Err(rustynet_crypto::CryptoError::OsStoreUnavailable)
            }
        }
        let source = OsSecureStoreControlDbKeySource::value_dek(BareStore);
        assert_eq!(source.load(), Err(DbKeyError::Unavailable));
        assert_eq!(load_or_provision(&source), Err(DbKeyError::Unavailable));
    }

    #[test]
    fn item_ids_are_valid_crypto_key_identifiers() {
        let id = CONTROL_DB_DEK_VALUE_ITEM_ID;
        assert!(!id.is_empty());
        assert!(id.len() <= 128);
        assert!(
            id.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'),
            "id {id} must satisfy is_valid_key_identifier"
        );
    }
}
