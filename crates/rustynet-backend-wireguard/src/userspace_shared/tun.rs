use std::fmt;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use rustynet_backend_api::{BackendError, RuntimeContext};
use tun_rs::{DeviceBuilder, SyncDevice};

use crate::linux_command::WireguardCommandRunner;

pub(crate) struct TunDevice {
    _inner: TunDeviceInner,
}

impl fmt::Debug for TunDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TunDevice(..)")
    }
}

impl TunDevice {
    fn real(device: SyncDevice) -> Self {
        Self {
            _inner: TunDeviceInner::Real(device),
        }
    }

    pub(crate) fn test_handle(state: TunTestState) -> Self {
        Self {
            _inner: TunDeviceInner::Test(TestTunDeviceHandle::new(state)),
        }
    }
}

#[allow(dead_code)]
enum TunDeviceInner {
    Real(SyncDevice),
    Test(TestTunDeviceHandle),
}

pub(crate) trait TunLifecycle: fmt::Debug + Send + Sync {
    fn prepare_and_open(
        &mut self,
        interface_name: &str,
        context: &RuntimeContext,
    ) -> Result<TunDevice, BackendError>;

    fn cleanup(&mut self, interface_name: &str) -> Result<(), BackendError>;
}

#[derive(Debug, Default)]
pub(crate) struct DirectTunLifecycle;

impl TunLifecycle for DirectTunLifecycle {
    fn prepare_and_open(
        &mut self,
        interface_name: &str,
        context: &RuntimeContext,
    ) -> Result<TunDevice, BackendError> {
        let local = ParsedLocalCidr::parse(&context.local_cidr)?;
        let device = DeviceBuilder::new()
            .name(interface_name)
            .ipv4(local.address, local.prefix_len, None::<Ipv4Addr>)
            .build_sync()
            .map_err(|err| {
                BackendError::internal(format!(
                    "linux userspace-shared TUN create/open failed for {interface_name}: {err}"
                ))
            })?;
        Ok(TunDevice::real(device))
    }

    fn cleanup(&mut self, _interface_name: &str) -> Result<(), BackendError> {
        Ok(())
    }
}

pub(crate) struct HelperBackedTunLifecycle {
    runner: Box<dyn WireguardCommandRunner + Send + Sync>,
    owner_uid: u32,
    owner_gid: u32,
}

impl fmt::Debug for HelperBackedTunLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelperBackedTunLifecycle")
            .field("owner_uid", &self.owner_uid)
            .field("owner_gid", &self.owner_gid)
            .finish()
    }
}

impl HelperBackedTunLifecycle {
    pub(crate) fn new<R>(runner: R, owner_uid: u32, owner_gid: u32) -> Self
    where
        R: WireguardCommandRunner + Send + Sync + 'static,
    {
        Self {
            runner: Box::new(runner),
            owner_uid,
            owner_gid,
        }
    }

    fn remove_interface_if_present(&mut self, interface_name: &str) -> Result<(), BackendError> {
        let args = vec![
            "link".to_string(),
            "del".to_string(),
            "dev".to_string(),
            interface_name.to_string(),
        ];
        match self.runner.run("ip", &args) {
            Ok(()) => Ok(()),
            Err(err) if is_missing_interface_error(&err) => Ok(()),
            Err(err) => Err(err),
        }
    }
}

impl TunLifecycle for HelperBackedTunLifecycle {
    fn prepare_and_open(
        &mut self,
        interface_name: &str,
        context: &RuntimeContext,
    ) -> Result<TunDevice, BackendError> {
        ParsedLocalCidr::parse(&context.local_cidr)?;
        self.remove_interface_if_present(interface_name)?;

        let result = (|| -> Result<TunDevice, BackendError> {
            self.runner.run(
                "ip",
                &[
                    "tuntap".to_string(),
                    "add".to_string(),
                    "dev".to_string(),
                    interface_name.to_string(),
                    "mode".to_string(),
                    "tun".to_string(),
                    "user".to_string(),
                    self.owner_uid.to_string(),
                    "group".to_string(),
                    self.owner_gid.to_string(),
                ],
            )?;
            self.runner.run(
                "ip",
                &[
                    "address".to_string(),
                    "add".to_string(),
                    context.local_cidr.clone(),
                    "dev".to_string(),
                    interface_name.to_string(),
                ],
            )?;
            self.runner.run(
                "ip",
                &[
                    "link".to_string(),
                    "set".to_string(),
                    "up".to_string(),
                    "dev".to_string(),
                    interface_name.to_string(),
                ],
            )?;

            let device = DeviceBuilder::new()
                .name(interface_name)
                .inherit_enable_state()
                .build_sync()
                .map_err(|err| {
                    BackendError::internal(format!(
                        "linux userspace-shared TUN open failed for {interface_name}: {err}"
                    ))
                })?;
            Ok(TunDevice::real(device))
        })();

        if result.is_err() {
            let _ = self.remove_interface_if_present(interface_name);
        }

        result
    }

    fn cleanup(&mut self, interface_name: &str) -> Result<(), BackendError> {
        self.remove_interface_if_present(interface_name)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TestTunLifecycle {
    state: TunTestState,
    behavior: TestTunBehavior,
}

impl Default for TestTunLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl TestTunLifecycle {
    pub(crate) fn new() -> Self {
        Self {
            state: TunTestState::default(),
            behavior: TestTunBehavior::Succeed,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn with_behavior(behavior: TestTunBehavior) -> Self {
        Self {
            state: TunTestState::default(),
            behavior,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn state(&self) -> TunTestState {
        self.state.clone()
    }
}

impl TunLifecycle for TestTunLifecycle {
    fn prepare_and_open(
        &mut self,
        interface_name: &str,
        context: &RuntimeContext,
    ) -> Result<TunDevice, BackendError> {
        self.state
            .record_prepare(interface_name, &context.local_cidr);
        match &self.behavior {
            TestTunBehavior::Succeed => Ok(TunDevice::test_handle(self.state.clone())),
            TestTunBehavior::FailBeforeOpen(message) => {
                Err(BackendError::internal(message.clone()))
            }
            TestTunBehavior::FailAfterOpen(message) => {
                drop(TunDevice::test_handle(self.state.clone()));
                Err(BackendError::internal(message.clone()))
            }
        }
    }

    fn cleanup(&mut self, interface_name: &str) -> Result<(), BackendError> {
        self.state.record_cleanup(interface_name);
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum TestTunBehavior {
    Succeed,
    FailBeforeOpen(String),
    FailAfterOpen(String),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TunTestState {
    inner: Arc<Mutex<TunTestStateInner>>,
}

impl TunTestState {
    fn record_prepare(&self, interface_name: &str, local_cidr: &str) {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.prepare_calls += 1;
        inner.last_interface_name = Some(interface_name.to_string());
        inner.last_local_cidr = Some(local_cidr.to_string());
    }

    fn record_cleanup(&self, interface_name: &str) {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.cleanup_calls += 1;
        inner.last_cleanup_interface_name = Some(interface_name.to_string());
    }

    fn increment_live_handles(&self) {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.live_handles += 1;
    }

    fn decrement_live_handles(&self) {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.live_handles = inner.live_handles.saturating_sub(1);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn snapshot(&self) -> TunTestSnapshot {
        let inner = self.inner.lock().expect("tun test state mutex poisoned");
        TunTestSnapshot {
            prepare_calls: inner.prepare_calls,
            cleanup_calls: inner.cleanup_calls,
            live_handles: inner.live_handles,
            last_interface_name: inner.last_interface_name.clone(),
            last_local_cidr: inner.last_local_cidr.clone(),
            last_cleanup_interface_name: inner.last_cleanup_interface_name.clone(),
        }
    }
}

#[derive(Debug, Default)]
struct TunTestStateInner {
    prepare_calls: usize,
    cleanup_calls: usize,
    live_handles: usize,
    last_interface_name: Option<String>,
    last_local_cidr: Option<String>,
    last_cleanup_interface_name: Option<String>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TunTestSnapshot {
    pub(crate) prepare_calls: usize,
    pub(crate) cleanup_calls: usize,
    pub(crate) live_handles: usize,
    pub(crate) last_interface_name: Option<String>,
    pub(crate) last_local_cidr: Option<String>,
    pub(crate) last_cleanup_interface_name: Option<String>,
}

#[derive(Debug)]
struct TestTunDeviceHandle {
    state: TunTestState,
}

impl TestTunDeviceHandle {
    fn new(state: TunTestState) -> Self {
        state.increment_live_handles();
        Self { state }
    }
}

impl Drop for TestTunDeviceHandle {
    fn drop(&mut self) {
        self.state.decrement_live_handles();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedLocalCidr {
    address: Ipv4Addr,
    prefix_len: u8,
}

impl ParsedLocalCidr {
    fn parse(value: &str) -> Result<Self, BackendError> {
        let (address, prefix_len) = value.split_once('/').ok_or_else(|| {
            BackendError::invalid_input(
                "linux userspace-shared local cidr must contain an address and prefix length",
            )
        })?;
        let address = address.parse::<Ipv4Addr>().map_err(|_| {
            BackendError::invalid_input(
                "linux userspace-shared backend currently requires an IPv4 local cidr",
            )
        })?;
        let prefix_len = prefix_len.parse::<u8>().map_err(|_| {
            BackendError::invalid_input(
                "linux userspace-shared local cidr prefix length must be numeric",
            )
        })?;
        if prefix_len > 32 {
            return Err(BackendError::invalid_input(
                "linux userspace-shared local cidr prefix length must be <= 32",
            ));
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }
}

fn is_missing_interface_error(err: &BackendError) -> bool {
    let message = err.message.to_ascii_lowercase();
    message.contains("cannot find device")
        || message.contains("does not exist")
        || message.contains("no such device")
        || message.contains("cannot find")
}
