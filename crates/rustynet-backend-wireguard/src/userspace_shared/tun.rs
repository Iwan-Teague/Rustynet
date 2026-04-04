use std::collections::VecDeque;
use std::fmt;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use rustynet_backend_api::{BackendError, ExitMode, Route, RouteKind, RuntimeContext};
use tun_rs::{DeviceBuilder, SyncDevice};

use crate::linux_command::{LinuxCommandRunner, WireguardCommandRunner, validate_interface_name};

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

    pub(crate) fn recv_packet(&self) -> Result<Option<Vec<u8>>, BackendError> {
        match &self._inner {
            TunDeviceInner::Real(device) => {
                let mut buffer = vec![0u8; 65_535];
                match device.recv(&mut buffer) {
                    Ok(len) => {
                        buffer.truncate(len);
                        Ok(Some(buffer))
                    }
                    Err(err)
                        if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                    {
                        Ok(None)
                    }
                    Err(err) => Err(BackendError::internal(format!(
                        "linux userspace-shared TUN receive failed: {err}"
                    ))),
                }
            }
            TunDeviceInner::Test(handle) => {
                if let Some(message) = handle.state.take_next_recv_error() {
                    return Err(BackendError::internal(message));
                }
                Ok(handle.dequeue_inbound_packet())
            }
        }
    }

    pub(crate) fn send_packet(&self, packet: &[u8]) -> Result<(), BackendError> {
        match &self._inner {
            TunDeviceInner::Real(device) => {
                let written = device.send(packet).map_err(|err| {
                    BackendError::internal(format!("linux userspace-shared TUN send failed: {err}"))
                })?;
                if written != packet.len() {
                    return Err(BackendError::internal(format!(
                        "linux userspace-shared TUN send truncated packet: wrote {written} of {} bytes",
                        packet.len()
                    )));
                }
                Ok(())
            }
            TunDeviceInner::Test(handle) => {
                handle.record_outbound_packet(packet.to_vec());
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn queue_inbound_packet_for_test(
        &self,
        packet: Vec<u8>,
    ) -> Result<(), BackendError> {
        match &self._inner {
            TunDeviceInner::Real(_) => Err(BackendError::internal(
                "real TUN device does not support test packet injection",
            )),
            TunDeviceInner::Test(handle) => {
                handle.queue_inbound_packet(packet);
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn recorded_outbound_packets_for_test(&self) -> Result<Vec<Vec<u8>>, BackendError> {
        match &self._inner {
            TunDeviceInner::Real(_) => Err(BackendError::internal(
                "real TUN device does not expose recorded outbound packets",
            )),
            TunDeviceInner::Test(handle) => Ok(handle.recorded_outbound_packets()),
        }
    }
}

#[allow(dead_code)]
enum TunDeviceInner {
    Real(SyncDevice),
    Test(TestTunDeviceHandle),
}

#[derive(Clone)]
pub(crate) struct SharedTunLifecycle {
    inner: Arc<Mutex<Box<dyn TunLifecycle>>>,
}

impl fmt::Debug for SharedTunLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedTunLifecycle(..)")
    }
}

impl SharedTunLifecycle {
    pub(crate) fn new(inner: Box<dyn TunLifecycle>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    pub(crate) fn prepare_and_open(
        &self,
        interface_name: &str,
        context: &RuntimeContext,
    ) -> Result<TunDevice, BackendError> {
        self.with_lock("prepare_and_open", |inner| {
            inner.prepare_and_open(interface_name, context)
        })
    }

    pub(crate) fn reconcile_routes(
        &self,
        interface_name: &str,
        previous_routes: &[Route],
        next_routes: &[Route],
    ) -> Result<(), BackendError> {
        self.with_lock("reconcile_routes", |inner| {
            inner.reconcile_routes(interface_name, previous_routes, next_routes)
        })
    }

    pub(crate) fn cleanup(&self, interface_name: &str) -> Result<(), BackendError> {
        self.with_lock("cleanup", |inner| inner.cleanup(interface_name))
    }

    pub(crate) fn reconcile_exit_mode(
        &self,
        previous_mode: ExitMode,
        next_mode: ExitMode,
    ) -> Result<(), BackendError> {
        self.with_lock("reconcile_exit_mode", |inner| {
            inner.reconcile_exit_mode(previous_mode, next_mode)
        })
    }

    fn with_lock<T>(
        &self,
        operation: &str,
        action: impl FnOnce(&mut dyn TunLifecycle) -> Result<T, BackendError>,
    ) -> Result<T, BackendError> {
        let mut guard = self.inner.lock().map_err(|_| {
            BackendError::internal(format!(
                "linux userspace-shared TUN lifecycle mutex poisoned during {operation}"
            ))
        })?;
        action(guard.as_mut())
    }
}

pub(crate) trait TunLifecycle: fmt::Debug + Send + Sync {
    fn prepare_and_open(
        &mut self,
        interface_name: &str,
        context: &RuntimeContext,
    ) -> Result<TunDevice, BackendError>;

    fn reconcile_routes(
        &mut self,
        interface_name: &str,
        previous_routes: &[Route],
        next_routes: &[Route],
    ) -> Result<(), BackendError>;

    fn reconcile_exit_mode(
        &mut self,
        previous_mode: ExitMode,
        next_mode: ExitMode,
    ) -> Result<(), BackendError>;

    fn cleanup(&mut self, interface_name: &str) -> Result<(), BackendError>;
}

#[derive(Debug, Default)]
pub(crate) struct DirectTunLifecycle {
    runner: LinuxCommandRunner,
}

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
        device.set_nonblocking(true).map_err(|err| {
            BackendError::internal(format!(
                "linux userspace-shared TUN nonblocking setup failed for {interface_name}: {err}"
            ))
        })?;
        Ok(TunDevice::real(device))
    }

    fn reconcile_routes(
        &mut self,
        interface_name: &str,
        previous_routes: &[Route],
        next_routes: &[Route],
    ) -> Result<(), BackendError> {
        reconcile_backend_routes(
            &mut self.runner,
            interface_name,
            previous_routes,
            next_routes,
        )
    }

    fn reconcile_exit_mode(
        &mut self,
        previous_mode: ExitMode,
        next_mode: ExitMode,
    ) -> Result<(), BackendError> {
        reconcile_backend_exit_mode(&mut self.runner, previous_mode, next_mode)
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
            device.set_nonblocking(true).map_err(|err| {
                BackendError::internal(format!(
                    "linux userspace-shared TUN nonblocking setup failed for {interface_name}: {err}"
                ))
            })?;
            Ok(TunDevice::real(device))
        })();

        if result.is_err() {
            let _ = self.remove_interface_if_present(interface_name);
        }

        result
    }

    fn reconcile_routes(
        &mut self,
        interface_name: &str,
        previous_routes: &[Route],
        next_routes: &[Route],
    ) -> Result<(), BackendError> {
        reconcile_backend_routes(
            self.runner.as_mut(),
            interface_name,
            previous_routes,
            next_routes,
        )
    }

    fn reconcile_exit_mode(
        &mut self,
        previous_mode: ExitMode,
        next_mode: ExitMode,
    ) -> Result<(), BackendError> {
        reconcile_backend_exit_mode(self.runner.as_mut(), previous_mode, next_mode)
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

    fn reconcile_routes(
        &mut self,
        interface_name: &str,
        previous_routes: &[Route],
        next_routes: &[Route],
    ) -> Result<(), BackendError> {
        validate_interface_name(interface_name)?;
        validate_route_set(next_routes)?;
        self.state.record_route_reconcile(interface_name);

        let previous_programmed = backend_programmed_route_cidrs(previous_routes);
        let next_programmed = backend_programmed_route_cidrs(next_routes);
        let route_behavior = self.state.route_behavior();

        let result = self.state.apply_route_reconciliation_for_test(
            &previous_programmed,
            &next_programmed,
            &route_behavior,
            true,
        );
        match result {
            Ok(()) => Ok(()),
            Err(err) => {
                let rollback_result = self.state.apply_route_reconciliation_for_test(
                    &next_programmed,
                    &previous_programmed,
                    &route_behavior,
                    false,
                );
                match rollback_result {
                    Ok(()) => Err(err),
                    Err(rollback_err) => Err(combine_route_reconciliation_error(err, rollback_err)),
                }
            }
        }
    }

    fn reconcile_exit_mode(
        &mut self,
        previous_mode: ExitMode,
        next_mode: ExitMode,
    ) -> Result<(), BackendError> {
        self.state.record_exit_mode_reconcile(next_mode);
        let exit_mode_behavior = self.state.exit_mode_behavior();

        let result = self
            .state
            .apply_exit_mode_plan_for_test(next_mode, &exit_mode_behavior, true);
        match result {
            Ok(()) => Ok(()),
            Err(err) => {
                let rollback_result = self.state.apply_exit_mode_plan_for_test(
                    previous_mode,
                    &exit_mode_behavior,
                    false,
                );
                match rollback_result {
                    Ok(()) => Err(err),
                    Err(rollback_err) => {
                        Err(combine_exit_mode_reconciliation_error(err, rollback_err))
                    }
                }
            }
        }
    }

    fn cleanup(&mut self, interface_name: &str) -> Result<(), BackendError> {
        self.state.record_cleanup(interface_name);
        self.state.clear_programmed_routes();
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

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TestRouteBehavior {
    Succeed,
    FailOnReplace { cidr: String, message: String },
    FailOnDelete { cidr: String, message: String },
}

impl Default for TestRouteBehavior {
    fn default() -> Self {
        Self::Succeed
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TestExitModeBehavior {
    Succeed,
    FailOnDeleteTable { message: String },
    FailOnDeletePriority { message: String },
    FailOnAddPriority { message: String },
}

impl Default for TestExitModeBehavior {
    fn default() -> Self {
        Self::Succeed
    }
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

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn set_next_recv_error(&self, message: impl Into<String>) {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.next_recv_error = Some(message.into());
    }

    fn increment_live_handles(&self) {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.live_handles += 1;
    }

    fn decrement_live_handles(&self) {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.live_handles = inner.live_handles.saturating_sub(1);
    }

    fn record_route_reconcile(&self, interface_name: &str) {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.route_reconcile_calls += 1;
        inner.last_route_interface_name = Some(interface_name.to_string());
    }

    fn clear_programmed_routes(&self) {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.programmed_route_cidrs.clear();
    }

    #[allow(dead_code)]
    fn queue_inbound_packet(&self, packet: Vec<u8>) {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.queued_inbound_packets.push_back(packet);
    }

    #[allow(dead_code)]
    fn dequeue_inbound_packet(&self) -> Option<Vec<u8>> {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.queued_inbound_packets.pop_front()
    }

    #[allow(dead_code)]
    fn take_next_recv_error(&self) -> Option<String> {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.next_recv_error.take()
    }

    #[allow(dead_code)]
    fn record_outbound_packet(&self, packet: Vec<u8>) {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.recorded_outbound_packets.push(packet);
    }

    #[allow(dead_code)]
    fn recorded_outbound_packets(&self) -> Vec<Vec<u8>> {
        let inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.recorded_outbound_packets.clone()
    }

    fn record_exit_mode_reconcile(&self, target_mode: ExitMode) {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.exit_mode_reconcile_calls += 1;
        inner.last_exit_mode_target = Some(target_mode);
    }

    fn route_behavior(&self) -> TestRouteBehavior {
        let inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.route_behavior.clone()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn set_route_behavior(&self, behavior: TestRouteBehavior) {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.route_behavior = behavior;
    }

    fn exit_mode_behavior(&self) -> TestExitModeBehavior {
        let inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.exit_mode_behavior.clone()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn set_exit_mode_behavior(&self, behavior: TestExitModeBehavior) {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");
        inner.exit_mode_behavior = behavior;
    }

    fn apply_route_reconciliation_for_test(
        &self,
        previous_programmed: &[String],
        next_programmed: &[String],
        route_behavior: &TestRouteBehavior,
        failures_enabled: bool,
    ) -> Result<(), BackendError> {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");

        for cidr in next_programmed {
            if failures_enabled {
                maybe_fail_route_replace(route_behavior, cidr)?;
            }
            if !inner
                .programmed_route_cidrs
                .iter()
                .any(|existing| existing == cidr)
            {
                inner.programmed_route_cidrs.push(cidr.clone());
            }
            inner.route_mutations.push(TunRouteMutation {
                kind: TunRouteMutationKind::Replace,
                destination_cidr: cidr.clone(),
            });
        }

        for cidr in previous_programmed {
            if next_programmed.iter().any(|next| next == cidr) {
                continue;
            }
            if failures_enabled {
                maybe_fail_route_delete(route_behavior, cidr)?;
            }
            inner
                .programmed_route_cidrs
                .retain(|existing| existing != cidr);
            inner.route_mutations.push(TunRouteMutation {
                kind: TunRouteMutationKind::Delete,
                destination_cidr: cidr.clone(),
            });
        }

        Ok(())
    }

    fn apply_exit_mode_plan_for_test(
        &self,
        mode: ExitMode,
        exit_mode_behavior: &TestExitModeBehavior,
        failures_enabled: bool,
    ) -> Result<(), BackendError> {
        let mut inner = self.inner.lock().expect("tun test state mutex poisoned");

        if failures_enabled {
            maybe_fail_exit_mode_delete_table(exit_mode_behavior)?;
        }
        inner
            .exit_mode_mutations
            .push(TunExitModeMutation::DeleteTable);

        if failures_enabled {
            maybe_fail_exit_mode_delete_priority(exit_mode_behavior)?;
        }
        inner
            .exit_mode_mutations
            .push(TunExitModeMutation::DeletePriority);

        match mode {
            ExitMode::Off => {
                inner.current_exit_mode = ExitMode::Off;
                Ok(())
            }
            ExitMode::FullTunnel => {
                if failures_enabled {
                    maybe_fail_exit_mode_add_priority(exit_mode_behavior)?;
                }
                inner
                    .exit_mode_mutations
                    .push(TunExitModeMutation::AddPriority);
                inner.current_exit_mode = ExitMode::FullTunnel;
                Ok(())
            }
        }
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
            route_reconcile_calls: inner.route_reconcile_calls,
            last_route_interface_name: inner.last_route_interface_name.clone(),
            programmed_route_cidrs: inner.programmed_route_cidrs.clone(),
            route_mutations: inner.route_mutations.clone(),
            exit_mode_reconcile_calls: inner.exit_mode_reconcile_calls,
            last_exit_mode_target: inner.last_exit_mode_target,
            current_exit_mode: inner.current_exit_mode,
            exit_mode_mutations: inner.exit_mode_mutations.clone(),
        }
    }
}

#[derive(Debug)]
struct TunTestStateInner {
    prepare_calls: usize,
    cleanup_calls: usize,
    live_handles: usize,
    last_interface_name: Option<String>,
    last_local_cidr: Option<String>,
    last_cleanup_interface_name: Option<String>,
    route_reconcile_calls: usize,
    last_route_interface_name: Option<String>,
    programmed_route_cidrs: Vec<String>,
    route_mutations: Vec<TunRouteMutation>,
    route_behavior: TestRouteBehavior,
    exit_mode_reconcile_calls: usize,
    last_exit_mode_target: Option<ExitMode>,
    current_exit_mode: ExitMode,
    exit_mode_mutations: Vec<TunExitModeMutation>,
    exit_mode_behavior: TestExitModeBehavior,
    queued_inbound_packets: VecDeque<Vec<u8>>,
    recorded_outbound_packets: Vec<Vec<u8>>,
    next_recv_error: Option<String>,
}

impl Default for TunTestStateInner {
    fn default() -> Self {
        Self {
            prepare_calls: 0,
            cleanup_calls: 0,
            live_handles: 0,
            last_interface_name: None,
            last_local_cidr: None,
            last_cleanup_interface_name: None,
            route_reconcile_calls: 0,
            last_route_interface_name: None,
            programmed_route_cidrs: Vec::new(),
            route_mutations: Vec::new(),
            route_behavior: TestRouteBehavior::default(),
            exit_mode_reconcile_calls: 0,
            last_exit_mode_target: None,
            current_exit_mode: ExitMode::Off,
            exit_mode_mutations: Vec::new(),
            exit_mode_behavior: TestExitModeBehavior::default(),
            queued_inbound_packets: VecDeque::new(),
            recorded_outbound_packets: Vec::new(),
            next_recv_error: None,
        }
    }
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
    pub(crate) route_reconcile_calls: usize,
    pub(crate) last_route_interface_name: Option<String>,
    pub(crate) programmed_route_cidrs: Vec<String>,
    pub(crate) route_mutations: Vec<TunRouteMutation>,
    pub(crate) exit_mode_reconcile_calls: usize,
    pub(crate) last_exit_mode_target: Option<ExitMode>,
    pub(crate) current_exit_mode: ExitMode,
    pub(crate) exit_mode_mutations: Vec<TunExitModeMutation>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TunRouteMutationKind {
    Replace,
    Delete,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TunRouteMutation {
    pub(crate) kind: TunRouteMutationKind,
    pub(crate) destination_cidr: String,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TunExitModeMutation {
    DeleteTable,
    DeletePriority,
    AddPriority,
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

    #[allow(dead_code)]
    fn queue_inbound_packet(&self, packet: Vec<u8>) {
        self.state.queue_inbound_packet(packet);
    }

    #[allow(dead_code)]
    fn dequeue_inbound_packet(&self) -> Option<Vec<u8>> {
        self.state.dequeue_inbound_packet()
    }

    #[allow(dead_code)]
    fn record_outbound_packet(&self, packet: Vec<u8>) {
        self.state.record_outbound_packet(packet);
    }

    #[allow(dead_code)]
    fn recorded_outbound_packets(&self) -> Vec<Vec<u8>> {
        self.state.recorded_outbound_packets()
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

fn reconcile_backend_routes(
    runner: &mut dyn WireguardCommandRunner,
    interface_name: &str,
    previous_routes: &[Route],
    next_routes: &[Route],
) -> Result<(), BackendError> {
    validate_interface_name(interface_name)?;
    validate_route_set(next_routes)?;

    let forward_result =
        apply_backend_route_plan(runner, interface_name, previous_routes, next_routes);
    match forward_result {
        Ok(()) => Ok(()),
        Err(err) => {
            let rollback_result =
                apply_backend_route_plan(runner, interface_name, next_routes, previous_routes);
            match rollback_result {
                Ok(()) => Err(err),
                Err(rollback_err) => Err(combine_route_reconciliation_error(err, rollback_err)),
            }
        }
    }
}

fn apply_backend_route_plan(
    runner: &mut dyn WireguardCommandRunner,
    interface_name: &str,
    previous_routes: &[Route],
    next_routes: &[Route],
) -> Result<(), BackendError> {
    for route in next_routes {
        if matches!(route.kind, RouteKind::ExitNodeDefault) {
            continue;
        }
        runner.run(
            "ip",
            &[
                "route".to_string(),
                "replace".to_string(),
                route.destination_cidr.clone(),
                "dev".to_string(),
                interface_name.to_string(),
            ],
        )?;
    }

    for route in previous_routes {
        if matches!(route.kind, RouteKind::ExitNodeDefault) {
            continue;
        }
        if next_routes.iter().any(|candidate| candidate == route) {
            continue;
        }
        match runner.run(
            "ip",
            &[
                "route".to_string(),
                "del".to_string(),
                route.destination_cidr.clone(),
                "dev".to_string(),
                interface_name.to_string(),
            ],
        ) {
            Ok(()) => {}
            Err(err) if is_missing_route_error(&err) => {}
            Err(err) => return Err(err),
        }
    }

    Ok(())
}

fn validate_route_set(routes: &[Route]) -> Result<(), BackendError> {
    for route in routes {
        validate_route_cidr(&route.destination_cidr)?;
    }
    Ok(())
}

fn validate_route_cidr(value: &str) -> Result<(), BackendError> {
    if value.is_empty() || !value.contains('/') {
        return Err(BackendError::invalid_input("invalid cidr value"));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == ':' || ch == '/')
    {
        return Err(BackendError::invalid_input(
            "cidr contains invalid characters",
        ));
    }
    Ok(())
}

fn backend_programmed_route_cidrs(routes: &[Route]) -> Vec<String> {
    routes
        .iter()
        .filter(|route| !matches!(route.kind, RouteKind::ExitNodeDefault))
        .map(|route| route.destination_cidr.clone())
        .collect()
}

fn combine_route_reconciliation_error(
    primary: BackendError,
    rollback: BackendError,
) -> BackendError {
    BackendError::internal(format!(
        "{}; route rollback failed: {}",
        primary.message, rollback.message
    ))
}

fn reconcile_backend_exit_mode(
    runner: &mut dyn WireguardCommandRunner,
    previous_mode: ExitMode,
    next_mode: ExitMode,
) -> Result<(), BackendError> {
    let forward_result = apply_backend_exit_mode_plan(runner, next_mode);
    match forward_result {
        Ok(()) => Ok(()),
        Err(err) => {
            let rollback_result = apply_backend_exit_mode_plan(runner, previous_mode);
            match rollback_result {
                Ok(()) => Err(err),
                Err(rollback_err) => Err(combine_exit_mode_reconciliation_error(err, rollback_err)),
            }
        }
    }
}

fn apply_backend_exit_mode_plan(
    runner: &mut dyn WireguardCommandRunner,
    mode: ExitMode,
) -> Result<(), BackendError> {
    clear_backend_exit_rules(runner)?;
    match mode {
        ExitMode::Off => Ok(()),
        ExitMode::FullTunnel => runner.run(
            "ip",
            &[
                "rule".to_string(),
                "add".to_string(),
                "priority".to_string(),
                "10000".to_string(),
                "table".to_string(),
                "51820".to_string(),
            ],
        ),
    }
}

fn clear_backend_exit_rules(runner: &mut dyn WireguardCommandRunner) -> Result<(), BackendError> {
    for _ in 0..64 {
        match runner.run(
            "ip",
            &[
                "rule".to_string(),
                "del".to_string(),
                "table".to_string(),
                "51820".to_string(),
            ],
        ) {
            Ok(()) => {}
            Err(err) if is_missing_rule_error(&err) => break,
            Err(err) => return Err(err),
        }
    }

    match runner.run(
        "ip",
        &[
            "rule".to_string(),
            "del".to_string(),
            "priority".to_string(),
            "10000".to_string(),
            "table".to_string(),
            "51820".to_string(),
        ],
    ) {
        Ok(()) => Ok(()),
        Err(err) if is_missing_rule_error(&err) => Ok(()),
        Err(err) => Err(err),
    }
}

fn combine_exit_mode_reconciliation_error(
    primary: BackendError,
    rollback: BackendError,
) -> BackendError {
    BackendError::internal(format!(
        "{}; exit-mode rollback failed: {}",
        primary.message, rollback.message
    ))
}

fn is_missing_interface_error(err: &BackendError) -> bool {
    let message = err.message.to_ascii_lowercase();
    message.contains("cannot find device")
        || message.contains("does not exist")
        || message.contains("no such device")
        || message.contains("cannot find")
}

fn is_missing_route_error(err: &BackendError) -> bool {
    let message = err.message.to_ascii_lowercase();
    message.contains("rtnetlink answers: no such process")
        || message.contains("no such process")
        || message.contains("no such file or directory")
}

fn is_missing_rule_error(err: &BackendError) -> bool {
    let message = err.message.to_ascii_lowercase();
    message.contains("rtnetlink answers: no such process")
        || message.contains("no such process")
        || message.contains("no such file or directory")
}

fn maybe_fail_route_replace(behavior: &TestRouteBehavior, cidr: &str) -> Result<(), BackendError> {
    match behavior {
        TestRouteBehavior::Succeed => Ok(()),
        TestRouteBehavior::FailOnReplace {
            cidr: target_cidr,
            message,
        } if target_cidr == cidr => Err(BackendError::internal(message.clone())),
        TestRouteBehavior::FailOnDelete { .. } => Ok(()),
        TestRouteBehavior::FailOnReplace { .. } => Ok(()),
    }
}

fn maybe_fail_route_delete(behavior: &TestRouteBehavior, cidr: &str) -> Result<(), BackendError> {
    match behavior {
        TestRouteBehavior::Succeed => Ok(()),
        TestRouteBehavior::FailOnDelete {
            cidr: target_cidr,
            message,
        } if target_cidr == cidr => Err(BackendError::internal(message.clone())),
        TestRouteBehavior::FailOnReplace { .. } => Ok(()),
        TestRouteBehavior::FailOnDelete { .. } => Ok(()),
    }
}

fn maybe_fail_exit_mode_delete_table(behavior: &TestExitModeBehavior) -> Result<(), BackendError> {
    match behavior {
        TestExitModeBehavior::Succeed => Ok(()),
        TestExitModeBehavior::FailOnDeleteTable { message } => {
            Err(BackendError::internal(message.clone()))
        }
        TestExitModeBehavior::FailOnDeletePriority { .. }
        | TestExitModeBehavior::FailOnAddPriority { .. } => Ok(()),
    }
}

fn maybe_fail_exit_mode_delete_priority(
    behavior: &TestExitModeBehavior,
) -> Result<(), BackendError> {
    match behavior {
        TestExitModeBehavior::Succeed => Ok(()),
        TestExitModeBehavior::FailOnDeletePriority { message } => {
            Err(BackendError::internal(message.clone()))
        }
        TestExitModeBehavior::FailOnDeleteTable { .. }
        | TestExitModeBehavior::FailOnAddPriority { .. } => Ok(()),
    }
}

fn maybe_fail_exit_mode_add_priority(behavior: &TestExitModeBehavior) -> Result<(), BackendError> {
    match behavior {
        TestExitModeBehavior::Succeed => Ok(()),
        TestExitModeBehavior::FailOnAddPriority { message } => {
            Err(BackendError::internal(message.clone()))
        }
        TestExitModeBehavior::FailOnDeleteTable { .. }
        | TestExitModeBehavior::FailOnDeletePriority { .. } => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use rustynet_backend_api::{ExitMode, NodeId, Route, RouteKind};

    use super::*;
    use crate::linux_command::WireguardCommandOutput;

    #[derive(Debug, Default)]
    struct RecordingRunner {
        commands: Vec<(String, Vec<String>)>,
    }

    impl WireguardCommandRunner for RecordingRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            self.commands.push((program.to_string(), args.to_vec()));
            Ok(())
        }

        fn run_capture(
            &mut self,
            program: &str,
            args: &[String],
        ) -> Result<WireguardCommandOutput, BackendError> {
            self.commands.push((program.to_string(), args.to_vec()));
            Ok(WireguardCommandOutput {
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    #[derive(Debug, Default)]
    struct MissingDeleteTableRunner {
        commands: Vec<(String, Vec<String>)>,
    }

    impl WireguardCommandRunner for MissingDeleteTableRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            self.commands.push((program.to_string(), args.to_vec()));
            let is_delete_table = program == "ip"
                && args
                    == ["rule", "del", "table", "51820"]
                        .iter()
                        .map(|value| value.to_string())
                        .collect::<Vec<_>>();
            if is_delete_table {
                return Err(BackendError::internal(
                    "privileged helper ip exited with status 2: RTNETLINK answers: No such process",
                ));
            }
            Ok(())
        }

        fn run_capture(
            &mut self,
            program: &str,
            args: &[String],
        ) -> Result<WireguardCommandOutput, BackendError> {
            self.run(program, args)?;
            Ok(WireguardCommandOutput {
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn route(destination_cidr: &str, kind: RouteKind) -> Route {
        Route {
            destination_cidr: destination_cidr.to_string(),
            via_node: NodeId::new("phase1-route-node").expect("valid node id"),
            kind,
        }
    }

    #[test]
    fn reconcile_backend_routes_skips_exit_node_default_on_add_and_delete() {
        let mut runner = RecordingRunner::default();

        reconcile_backend_routes(
            &mut runner,
            "rustynet0",
            &[
                route("100.64.20.0/24", RouteKind::Mesh),
                route("0.0.0.0/0", RouteKind::ExitNodeDefault),
            ],
            &[
                route("100.64.30.0/24", RouteKind::ExitNodeLan),
                route("0.0.0.0/0", RouteKind::ExitNodeDefault),
            ],
        )
        .expect("route reconciliation should succeed");

        assert_eq!(
            runner.commands,
            vec![
                (
                    "ip".to_string(),
                    vec![
                        "route".to_string(),
                        "replace".to_string(),
                        "100.64.30.0/24".to_string(),
                        "dev".to_string(),
                        "rustynet0".to_string(),
                    ],
                ),
                (
                    "ip".to_string(),
                    vec![
                        "route".to_string(),
                        "del".to_string(),
                        "100.64.20.0/24".to_string(),
                        "dev".to_string(),
                        "rustynet0".to_string(),
                    ],
                ),
            ]
        );
    }

    #[test]
    fn reconcile_backend_exit_mode_full_tunnel_uses_fixed_priority_rule() {
        let mut runner = MissingDeleteTableRunner::default();

        reconcile_backend_exit_mode(&mut runner, ExitMode::Off, ExitMode::FullTunnel)
            .expect("exit-mode reconciliation should succeed");

        let delete_priority = vec![
            "rule".to_string(),
            "del".to_string(),
            "priority".to_string(),
            "10000".to_string(),
            "table".to_string(),
            "51820".to_string(),
        ];
        let add_priority = vec![
            "rule".to_string(),
            "add".to_string(),
            "priority".to_string(),
            "10000".to_string(),
            "table".to_string(),
            "51820".to_string(),
        ];

        assert!(
            runner
                .commands
                .iter()
                .any(|(program, args)| program == "ip" && args == &delete_priority)
        );
        assert!(
            runner
                .commands
                .iter()
                .any(|(program, args)| program == "ip" && args == &add_priority)
        );
    }
}
