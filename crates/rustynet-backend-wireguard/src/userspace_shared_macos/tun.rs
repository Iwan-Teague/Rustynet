#![allow(dead_code)]

use std::collections::{BTreeSet, VecDeque};
use std::fmt;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use rustynet_backend_api::{
    BackendError, ExitMode, PeerConfig, Route, RouteKind, RuntimeContext, SocketEndpoint,
};
use rustynet_tun::SyncDevice;

use crate::linux_command::{
    LinuxCommandRunner, WireguardCommandOutput, WireguardCommandRunner, validate_interface_name,
};

pub(crate) struct MacosTunDevice {
    inner: MacosTunDeviceInner,
}

impl fmt::Debug for MacosTunDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MacosTunDevice(..)")
    }
}

impl MacosTunDevice {
    fn real(device: SyncDevice) -> Self {
        Self {
            inner: MacosTunDeviceInner::Real(device),
        }
    }

    pub(crate) fn test_handle(state: MacosTunTestState) -> Self {
        Self {
            inner: MacosTunDeviceInner::Test(MacosTestTunDeviceHandle::new(state)),
        }
    }

    pub(crate) fn recv_packet(&self) -> Result<Option<Vec<u8>>, BackendError> {
        match &self.inner {
            MacosTunDeviceInner::Real(device) => {
                let mut buffer = vec![0u8; 65_535];
                match device.recv(&mut buffer) {
                    Ok(len) => {
                        if len == 0 {
                            return Ok(None);
                        }
                        buffer.truncate(len);
                        Ok(Some(buffer))
                    }
                    Err(err)
                        if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                    {
                        Ok(None)
                    }
                    Err(err) => Err(BackendError::internal(format!(
                        "macos userspace-shared TUN receive failed: {err}"
                    ))),
                }
            }
            MacosTunDeviceInner::Test(handle) => {
                if let Some(message) = handle.state.take_next_recv_error() {
                    return Err(BackendError::internal(message));
                }
                Ok(handle.dequeue_nonempty_inbound_packet())
            }
        }
    }

    pub(crate) fn send_packet(&self, packet: &[u8]) -> Result<(), BackendError> {
        match &self.inner {
            MacosTunDeviceInner::Real(device) => {
                let written = device.send(packet).map_err(|err| {
                    BackendError::internal(format!("macos userspace-shared TUN send failed: {err}"))
                })?;
                if written != packet.len() {
                    return Err(BackendError::internal(format!(
                        "macos userspace-shared TUN send truncated packet: wrote {written} of {} bytes",
                        packet.len()
                    )));
                }
                Ok(())
            }
            MacosTunDeviceInner::Test(handle) => {
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
        match &self.inner {
            MacosTunDeviceInner::Real(_) => Err(BackendError::internal(
                "real macos TUN device does not support test packet injection",
            )),
            MacosTunDeviceInner::Test(handle) => {
                handle.queue_inbound_packet(packet);
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn recorded_outbound_packets_for_test(&self) -> Result<Vec<Vec<u8>>, BackendError> {
        match &self.inner {
            MacosTunDeviceInner::Real(_) => Err(BackendError::internal(
                "real macos TUN device does not expose recorded outbound packets",
            )),
            MacosTunDeviceInner::Test(handle) => Ok(handle.recorded_outbound_packets()),
        }
    }
}

enum MacosTunDeviceInner {
    Real(SyncDevice),
    Test(MacosTestTunDeviceHandle),
}

#[derive(Clone)]
pub(crate) struct SharedMacosTunLifecycle {
    inner: Arc<Mutex<Box<dyn MacosTunLifecycle>>>,
}

impl fmt::Debug for SharedMacosTunLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedMacosTunLifecycle(..)")
    }
}

impl SharedMacosTunLifecycle {
    pub(crate) fn new(inner: Box<dyn MacosTunLifecycle>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    pub(crate) fn prepare_and_open(
        &self,
        interface_name: &str,
        context: &RuntimeContext,
    ) -> Result<MacosTunDevice, BackendError> {
        self.with_lock("prepare_and_open", |inner| {
            inner.prepare_and_open(interface_name, context)
        })
    }

    pub(crate) fn cleanup(&self, interface_name: &str) -> Result<(), BackendError> {
        self.with_lock("cleanup", |inner| inner.cleanup(interface_name))
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

    pub(crate) fn reconcile_exit_mode(
        &self,
        interface_name: &str,
        previous_mode: ExitMode,
        next_mode: ExitMode,
        peers: &[PeerConfig],
    ) -> Result<(), BackendError> {
        self.with_lock("reconcile_exit_mode", |inner| {
            inner.reconcile_exit_mode(interface_name, previous_mode, next_mode, peers)
        })
    }

    fn with_lock<T>(
        &self,
        operation: &str,
        action: impl FnOnce(&mut dyn MacosTunLifecycle) -> Result<T, BackendError>,
    ) -> Result<T, BackendError> {
        let mut guard = self.inner.lock().map_err(|_| {
            BackendError::internal(format!(
                "macos userspace-shared TUN lifecycle mutex poisoned during {operation}"
            ))
        })?;
        action(guard.as_mut())
    }
}

pub(crate) trait MacosTunLifecycle: fmt::Debug + Send + Sync {
    fn prepare_and_open(
        &mut self,
        interface_name: &str,
        context: &RuntimeContext,
    ) -> Result<MacosTunDevice, BackendError>;

    fn reconcile_routes(
        &mut self,
        interface_name: &str,
        previous_routes: &[Route],
        next_routes: &[Route],
    ) -> Result<(), BackendError>;

    fn reconcile_exit_mode(
        &mut self,
        interface_name: &str,
        previous_mode: ExitMode,
        next_mode: ExitMode,
        peers: &[PeerConfig],
    ) -> Result<(), BackendError>;

    fn cleanup(&mut self, interface_name: &str) -> Result<(), BackendError>;
}

pub(crate) struct DirectMacosTunLifecycle {
    runner: Box<dyn WireguardCommandRunner + Send + Sync>,
    default_route: Option<MacosDefaultRoute>,
    endpoint_bypass_hosts: BTreeSet<IpAddr>,
    #[cfg(target_os = "macos")]
    utun_opener: Option<crate::MacosUtunOpenerFn>,
}

impl fmt::Debug for DirectMacosTunLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectMacosTunLifecycle")
            .field("default_route", &self.default_route)
            .finish_non_exhaustive()
    }
}

impl Default for DirectMacosTunLifecycle {
    fn default() -> Self {
        Self {
            runner: Box::new(LinuxCommandRunner),
            default_route: None,
            endpoint_bypass_hosts: BTreeSet::new(),
            #[cfg(target_os = "macos")]
            utun_opener: None,
        }
    }
}

impl DirectMacosTunLifecycle {
    #[cfg(target_os = "macos")]
    pub(crate) fn with_utun_opener(opener: crate::MacosUtunOpenerFn) -> Self {
        Self {
            utun_opener: Some(opener),
            ..Self::default()
        }
    }

    /// Build a lifecycle that routes ifconfig / route invocations through the
    /// privileged helper while still opening utun via SCM_RIGHTS from the
    /// helper. The macOS daemon runs as `User=rustynetd` (uid 500); ifconfig
    /// ioctls (SIOCAIFADDR / SIOCDIFADDR) and `route add/delete` need root.
    /// The helper accepts `PrivilegedCommandProgram::Ifconfig` and `Route`,
    /// so the runner threaded in here is `PrivilegedHelperWireguardRunner`
    /// from `rustynetd::privileged_helper`.
    #[cfg(target_os = "macos")]
    pub(crate) fn with_helper_runner_and_utun_opener<R>(
        runner: R,
        opener: crate::MacosUtunOpenerFn,
    ) -> Self
    where
        R: WireguardCommandRunner + Send + Sync + 'static,
    {
        Self {
            runner: Box::new(runner),
            default_route: None,
            endpoint_bypass_hosts: BTreeSet::new(),
            utun_opener: Some(opener),
        }
    }
}

impl MacosTunLifecycle for DirectMacosTunLifecycle {
    fn prepare_and_open(
        &mut self,
        interface_name: &str,
        context: &RuntimeContext,
    ) -> Result<MacosTunDevice, BackendError> {
        validate_macos_utun_name(interface_name)?;
        let local = ParsedLocalCidr::parse(&context.local_cidr)?;
        #[cfg(target_os = "macos")]
        let device = open_utun_device(interface_name, self.utun_opener.as_deref())?;
        #[cfg(not(target_os = "macos"))]
        let device = SyncDevice::open(interface_name).map_err(|err| {
            BackendError::internal(format!(
                "macos userspace-shared utun open failed for {interface_name}: {err}"
            ))
        })?;
        device.set_nonblocking(true).map_err(|err| {
            BackendError::internal(format!(
                "macos userspace-shared utun nonblocking setup failed for {interface_name}: {err}"
            ))
        })?;

        let result = (|| -> Result<(), BackendError> {
            configure_macos_utun_address(&mut *self.runner, interface_name, local.address)?;
            self.runner
                .run("ifconfig", &[interface_name.to_owned(), "up".to_owned()])?;
            Ok(())
        })();

        match result {
            Ok(()) => Ok(MacosTunDevice::real(device)),
            Err(err) => {
                drop(device);
                match self.cleanup(interface_name) {
                    Ok(()) => Err(err),
                    Err(cleanup_err) => Err(combine_tun_start_cleanup_error(err, cleanup_err)),
                }
            }
        }
    }

    fn cleanup(&mut self, interface_name: &str) -> Result<(), BackendError> {
        cleanup_macos_runtime_state(
            &mut *self.runner,
            &mut self.default_route,
            &mut self.endpoint_bypass_hosts,
            interface_name,
        )
    }

    fn reconcile_routes(
        &mut self,
        interface_name: &str,
        previous_routes: &[Route],
        next_routes: &[Route],
    ) -> Result<(), BackendError> {
        reconcile_macos_backend_routes(
            &mut *self.runner,
            interface_name,
            previous_routes,
            next_routes,
        )
    }

    fn reconcile_exit_mode(
        &mut self,
        interface_name: &str,
        previous_mode: ExitMode,
        next_mode: ExitMode,
        peers: &[PeerConfig],
    ) -> Result<(), BackendError> {
        reconcile_macos_exit_mode(
            &mut *self.runner,
            interface_name,
            previous_mode,
            next_mode,
            peers,
            &mut self.default_route,
            &mut self.endpoint_bypass_hosts,
        )
    }
}

fn cleanup_macos_runtime_state(
    runner: &mut dyn WireguardCommandRunner,
    default_route: &mut Option<MacosDefaultRoute>,
    endpoint_bypass_hosts: &mut BTreeSet<IpAddr>,
    interface_name: &str,
) -> Result<(), BackendError> {
    let route_cleanup = restore_macos_default_route(runner, default_route, endpoint_bypass_hosts);
    let interface_cleanup = cleanup_macos_utun(runner, interface_name);
    match (route_cleanup, interface_cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(err), Ok(())) | (Ok(()), Err(err)) => Err(err),
        (Err(primary), Err(cleanup)) => Err(combine_macos_cleanup_error(primary, cleanup)),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TestMacosTunLifecycle {
    state: MacosTunTestState,
    behavior: MacosTunTestBehavior,
}

impl Default for TestMacosTunLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl TestMacosTunLifecycle {
    pub(crate) fn new() -> Self {
        Self {
            state: MacosTunTestState::default(),
            behavior: MacosTunTestBehavior::Succeed,
        }
    }

    pub(crate) fn with_behavior(behavior: MacosTunTestBehavior) -> Self {
        Self {
            state: MacosTunTestState::default(),
            behavior,
        }
    }

    pub(crate) fn state(&self) -> MacosTunTestState {
        self.state.clone()
    }
}

impl MacosTunLifecycle for TestMacosTunLifecycle {
    fn prepare_and_open(
        &mut self,
        interface_name: &str,
        context: &RuntimeContext,
    ) -> Result<MacosTunDevice, BackendError> {
        validate_macos_utun_name(interface_name)?;
        ParsedLocalCidr::parse(&context.local_cidr)?;
        self.state
            .record_prepare(interface_name, &context.local_cidr);
        match &self.behavior {
            MacosTunTestBehavior::Succeed => Ok(MacosTunDevice::test_handle(self.state.clone())),
            MacosTunTestBehavior::FailBeforeOpen(message) => {
                Err(BackendError::internal(message.clone()))
            }
            MacosTunTestBehavior::FailAfterOpen(message) => {
                drop(MacosTunDevice::test_handle(self.state.clone()));
                Err(BackendError::internal(message.clone()))
            }
        }
    }

    fn cleanup(&mut self, interface_name: &str) -> Result<(), BackendError> {
        validate_macos_utun_name(interface_name)?;
        self.state.record_cleanup(interface_name);
        if let MacosTestCleanupBehavior::Fail { message } = self.state.cleanup_behavior() {
            return Err(BackendError::internal(message));
        }
        self.state.clear_programmed_state();
        Ok(())
    }

    fn reconcile_routes(
        &mut self,
        interface_name: &str,
        previous_routes: &[Route],
        next_routes: &[Route],
    ) -> Result<(), BackendError> {
        validate_macos_utun_name(interface_name)?;
        let previous_programmed = backend_programmed_route_cidrs(previous_routes)?;
        let next_programmed = backend_programmed_route_cidrs(next_routes)?;
        self.state
            .record_route_reconcile(interface_name, previous_routes, next_routes);
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
        interface_name: &str,
        previous_mode: ExitMode,
        next_mode: ExitMode,
        peers: &[PeerConfig],
    ) -> Result<(), BackendError> {
        validate_macos_utun_name(interface_name)?;
        self.state
            .record_exit_mode_reconcile(previous_mode, next_mode, peers);
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MacosTunTestBehavior {
    Succeed,
    FailBeforeOpen(String),
    FailAfterOpen(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum MacosTestRouteBehavior {
    #[default]
    Succeed,
    FailOnAdd {
        cidr: String,
        message: String,
    },
    FailOnDelete {
        cidr: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum MacosTestExitModeBehavior {
    #[default]
    Succeed,
    FailOnFullTunnel {
        message: String,
    },
    FailOnOff {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum MacosTestCleanupBehavior {
    #[default]
    Succeed,
    Fail {
        message: String,
    },
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MacosTunTestState {
    inner: Arc<Mutex<MacosTunTestStateInner>>,
}

impl MacosTunTestState {
    fn record_prepare(&self, interface_name: &str, local_cidr: &str) {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.prepare_calls += 1;
        inner.last_interface_name = Some(interface_name.to_owned());
        inner.last_local_cidr = Some(local_cidr.to_owned());
    }

    fn record_cleanup(&self, interface_name: &str) {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.cleanup_calls += 1;
        inner.last_cleanup_interface_name = Some(interface_name.to_owned());
    }

    fn record_route_reconcile(
        &self,
        interface_name: &str,
        previous_routes: &[Route],
        next_routes: &[Route],
    ) {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.route_reconcile_calls += 1;
        inner.last_route_reconcile_interface_name = Some(interface_name.to_owned());
        inner.last_previous_routes = previous_routes.to_vec();
        inner.last_next_routes = next_routes.to_vec();
    }

    fn route_behavior(&self) -> MacosTestRouteBehavior {
        let inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.route_behavior.clone()
    }

    pub(crate) fn set_route_behavior(&self, behavior: MacosTestRouteBehavior) {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.route_behavior = behavior;
    }

    fn apply_route_reconciliation_for_test(
        &self,
        previous_programmed: &[ParsedRouteCidr],
        next_programmed: &[ParsedRouteCidr],
        route_behavior: &MacosTestRouteBehavior,
        failures_enabled: bool,
    ) -> Result<(), BackendError> {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");

        for cidr in next_programmed {
            let route_arg = cidr.route_arg();
            if previous_programmed.iter().any(|previous| previous == cidr) {
                continue;
            }
            if failures_enabled {
                maybe_fail_macos_route_add(route_behavior, &route_arg)?;
            }
            if !inner
                .programmed_route_cidrs
                .iter()
                .any(|existing| existing == &route_arg)
            {
                inner.programmed_route_cidrs.push(route_arg.clone());
            }
        }

        for cidr in previous_programmed {
            let route_arg = cidr.route_arg();
            if next_programmed.iter().any(|next| next == cidr) {
                continue;
            }
            if failures_enabled {
                maybe_fail_macos_route_delete(route_behavior, &route_arg)?;
            }
            inner
                .programmed_route_cidrs
                .retain(|existing| existing != &route_arg);
        }

        Ok(())
    }

    fn record_exit_mode_reconcile(
        &self,
        previous_mode: ExitMode,
        next_mode: ExitMode,
        peers: &[PeerConfig],
    ) {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.exit_mode_reconcile_calls += 1;
        inner.last_previous_exit_mode = Some(previous_mode);
        inner.last_next_exit_mode = Some(next_mode);
        inner.last_exit_mode_peer_endpoints = peers.iter().map(|peer| peer.endpoint).collect();
    }

    fn exit_mode_behavior(&self) -> MacosTestExitModeBehavior {
        let inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.exit_mode_behavior.clone()
    }

    pub(crate) fn set_exit_mode_behavior(&self, behavior: MacosTestExitModeBehavior) {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.exit_mode_behavior = behavior;
    }

    pub(crate) fn set_cleanup_behavior(&self, behavior: MacosTestCleanupBehavior) {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.cleanup_behavior = behavior;
    }

    fn apply_exit_mode_plan_for_test(
        &self,
        mode: ExitMode,
        behavior: &MacosTestExitModeBehavior,
        failures_enabled: bool,
    ) -> Result<(), BackendError> {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        if failures_enabled {
            maybe_fail_macos_exit_mode(behavior, mode)?;
        }
        inner.current_exit_mode = mode;
        Ok(())
    }

    fn cleanup_behavior(&self) -> MacosTestCleanupBehavior {
        let inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.cleanup_behavior.clone()
    }

    fn clear_programmed_state(&self) {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.programmed_route_cidrs.clear();
        inner.current_exit_mode = ExitMode::Off;
    }

    fn increment_live_handles(&self) {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.live_handles += 1;
    }

    fn decrement_live_handles(&self) {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.live_handles = inner.live_handles.saturating_sub(1);
    }

    fn queue_inbound_packet(&self, packet: Vec<u8>) {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.queued_inbound_packets.push_back(packet);
    }

    fn dequeue_inbound_packet(&self) -> Option<Vec<u8>> {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.queued_inbound_packets.pop_front()
    }

    pub(crate) fn set_next_recv_error(&self, message: impl Into<String>) {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.next_recv_error = Some(message.into());
    }

    fn take_next_recv_error(&self) -> Option<String> {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.next_recv_error.take()
    }

    fn record_outbound_packet(&self, packet: Vec<u8>) {
        let mut inner = self.inner.lock().expect("macos tun test state poisoned");
        inner.recorded_outbound_packets.push(packet);
    }

    pub(crate) fn snapshot(&self) -> MacosTunTestSnapshot {
        let inner = self.inner.lock().expect("macos tun test state poisoned");
        MacosTunTestSnapshot {
            prepare_calls: inner.prepare_calls,
            cleanup_calls: inner.cleanup_calls,
            live_handles: inner.live_handles,
            last_interface_name: inner.last_interface_name.clone(),
            last_local_cidr: inner.last_local_cidr.clone(),
            last_cleanup_interface_name: inner.last_cleanup_interface_name.clone(),
            route_reconcile_calls: inner.route_reconcile_calls,
            last_route_reconcile_interface_name: inner.last_route_reconcile_interface_name.clone(),
            last_previous_routes: inner.last_previous_routes.clone(),
            last_next_routes: inner.last_next_routes.clone(),
            programmed_route_cidrs: inner.programmed_route_cidrs.clone(),
            exit_mode_reconcile_calls: inner.exit_mode_reconcile_calls,
            last_previous_exit_mode: inner.last_previous_exit_mode,
            last_next_exit_mode: inner.last_next_exit_mode,
            last_exit_mode_peer_endpoints: inner.last_exit_mode_peer_endpoints.clone(),
            current_exit_mode: inner.current_exit_mode,
            queued_inbound_packets: inner.queued_inbound_packets.len(),
            recorded_outbound_packets: inner.recorded_outbound_packets.clone(),
        }
    }
}

#[derive(Debug)]
struct MacosTunTestStateInner {
    prepare_calls: usize,
    cleanup_calls: usize,
    live_handles: usize,
    last_interface_name: Option<String>,
    last_local_cidr: Option<String>,
    last_cleanup_interface_name: Option<String>,
    route_reconcile_calls: usize,
    last_route_reconcile_interface_name: Option<String>,
    last_previous_routes: Vec<Route>,
    last_next_routes: Vec<Route>,
    programmed_route_cidrs: Vec<String>,
    route_behavior: MacosTestRouteBehavior,
    exit_mode_reconcile_calls: usize,
    last_previous_exit_mode: Option<ExitMode>,
    last_next_exit_mode: Option<ExitMode>,
    last_exit_mode_peer_endpoints: Vec<SocketEndpoint>,
    current_exit_mode: ExitMode,
    exit_mode_behavior: MacosTestExitModeBehavior,
    cleanup_behavior: MacosTestCleanupBehavior,
    queued_inbound_packets: VecDeque<Vec<u8>>,
    recorded_outbound_packets: Vec<Vec<u8>>,
    next_recv_error: Option<String>,
}

impl Default for MacosTunTestStateInner {
    fn default() -> Self {
        Self {
            prepare_calls: 0,
            cleanup_calls: 0,
            live_handles: 0,
            last_interface_name: None,
            last_local_cidr: None,
            last_cleanup_interface_name: None,
            route_reconcile_calls: 0,
            last_route_reconcile_interface_name: None,
            last_previous_routes: Vec::new(),
            last_next_routes: Vec::new(),
            programmed_route_cidrs: Vec::new(),
            route_behavior: MacosTestRouteBehavior::default(),
            exit_mode_reconcile_calls: 0,
            last_previous_exit_mode: None,
            last_next_exit_mode: None,
            last_exit_mode_peer_endpoints: Vec::new(),
            current_exit_mode: ExitMode::Off,
            exit_mode_behavior: MacosTestExitModeBehavior::default(),
            cleanup_behavior: MacosTestCleanupBehavior::default(),
            queued_inbound_packets: VecDeque::new(),
            recorded_outbound_packets: Vec::new(),
            next_recv_error: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MacosTunTestSnapshot {
    pub(crate) prepare_calls: usize,
    pub(crate) cleanup_calls: usize,
    pub(crate) live_handles: usize,
    pub(crate) last_interface_name: Option<String>,
    pub(crate) last_local_cidr: Option<String>,
    pub(crate) last_cleanup_interface_name: Option<String>,
    pub(crate) route_reconcile_calls: usize,
    pub(crate) last_route_reconcile_interface_name: Option<String>,
    pub(crate) last_previous_routes: Vec<Route>,
    pub(crate) last_next_routes: Vec<Route>,
    pub(crate) programmed_route_cidrs: Vec<String>,
    pub(crate) exit_mode_reconcile_calls: usize,
    pub(crate) last_previous_exit_mode: Option<ExitMode>,
    pub(crate) last_next_exit_mode: Option<ExitMode>,
    pub(crate) last_exit_mode_peer_endpoints: Vec<SocketEndpoint>,
    pub(crate) current_exit_mode: ExitMode,
    pub(crate) queued_inbound_packets: usize,
    pub(crate) recorded_outbound_packets: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct MacosTestTunDeviceHandle {
    state: MacosTunTestState,
}

impl MacosTestTunDeviceHandle {
    fn new(state: MacosTunTestState) -> Self {
        state.increment_live_handles();
        Self { state }
    }

    fn queue_inbound_packet(&self, packet: Vec<u8>) {
        self.state.queue_inbound_packet(packet);
    }

    fn dequeue_nonempty_inbound_packet(&self) -> Option<Vec<u8>> {
        while let Some(packet) = self.state.dequeue_inbound_packet() {
            if !packet.is_empty() {
                return Some(packet);
            }
        }
        None
    }

    fn record_outbound_packet(&self, packet: Vec<u8>) {
        self.state.record_outbound_packet(packet);
    }

    fn recorded_outbound_packets(&self) -> Vec<Vec<u8>> {
        self.state.snapshot().recorded_outbound_packets
    }
}

impl Drop for MacosTestTunDeviceHandle {
    fn drop(&mut self) {
        self.state.decrement_live_handles();
    }
}

fn maybe_fail_macos_route_add(
    behavior: &MacosTestRouteBehavior,
    cidr: &str,
) -> Result<(), BackendError> {
    match behavior {
        MacosTestRouteBehavior::Succeed | MacosTestRouteBehavior::FailOnDelete { .. } => Ok(()),
        MacosTestRouteBehavior::FailOnAdd {
            cidr: target,
            message,
        } if target == cidr => Err(BackendError::internal(message.clone())),
        MacosTestRouteBehavior::FailOnAdd { .. } => Ok(()),
    }
}

fn maybe_fail_macos_route_delete(
    behavior: &MacosTestRouteBehavior,
    cidr: &str,
) -> Result<(), BackendError> {
    match behavior {
        MacosTestRouteBehavior::Succeed | MacosTestRouteBehavior::FailOnAdd { .. } => Ok(()),
        MacosTestRouteBehavior::FailOnDelete {
            cidr: target,
            message,
        } if target == cidr => Err(BackendError::internal(message.clone())),
        MacosTestRouteBehavior::FailOnDelete { .. } => Ok(()),
    }
}

fn maybe_fail_macos_exit_mode(
    behavior: &MacosTestExitModeBehavior,
    mode: ExitMode,
) -> Result<(), BackendError> {
    match (behavior, mode) {
        (MacosTestExitModeBehavior::Succeed, _)
        | (MacosTestExitModeBehavior::FailOnFullTunnel { .. }, ExitMode::Off)
        | (MacosTestExitModeBehavior::FailOnOff { .. }, ExitMode::FullTunnel) => Ok(()),
        (MacosTestExitModeBehavior::FailOnFullTunnel { message }, ExitMode::FullTunnel)
        | (MacosTestExitModeBehavior::FailOnOff { message }, ExitMode::Off) => {
            Err(BackendError::internal(message.clone()))
        }
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
                "macos userspace-shared local cidr must contain an address and prefix length",
            )
        })?;
        let address = address.parse::<Ipv4Addr>().map_err(|_| {
            BackendError::invalid_input(
                "macos userspace-shared backend currently requires an IPv4 local cidr",
            )
        })?;
        let prefix_len = prefix_len.parse::<u8>().map_err(|_| {
            BackendError::invalid_input(
                "macos userspace-shared local cidr prefix length must be numeric",
            )
        })?;
        if prefix_len > 32 {
            return Err(BackendError::invalid_input(
                "macos userspace-shared local cidr prefix length must be <= 32",
            ));
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }
}

#[cfg(target_os = "macos")]
type MacosUtunOpener = dyn Fn(&str) -> Result<std::os::fd::OwnedFd, String> + Send + Sync;

#[cfg(target_os = "macos")]
fn open_utun_device(
    interface_name: &str,
    opener_fn: Option<&MacosUtunOpener>,
) -> Result<SyncDevice, BackendError> {
    match opener_fn {
        None => SyncDevice::open(interface_name).map_err(|err| {
            BackendError::internal(format!(
                "macos userspace-shared utun open failed for {interface_name}: {err}"
            ))
        }),
        Some(open_fn) => {
            use std::os::fd::IntoRawFd;
            let owned_fd = open_fn(interface_name).map_err(|err| {
                BackendError::internal(format!(
                    "macos userspace-shared utun privileged-helper open failed for {interface_name}: {err}"
                ))
            })?;
            let raw_fd = owned_fd.into_raw_fd();
            SyncDevice::from_raw_fd(raw_fd).map_err(|err| {
                BackendError::internal(format!(
                    "macos userspace-shared utun fd wrap failed for {interface_name}: {err}"
                ))
            })
        }
    }
}

fn validate_macos_utun_name(interface_name: &str) -> Result<(), BackendError> {
    validate_interface_name(interface_name)?;
    let suffix = interface_name.strip_prefix("utun").ok_or_else(|| {
        BackendError::invalid_input("macos userspace-shared interface name must start with utun")
    })?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BackendError::invalid_input(
            "macos userspace-shared interface name must be utun followed by digits",
        ));
    }
    Ok(())
}

fn configure_macos_utun_address(
    runner: &mut dyn WireguardCommandRunner,
    interface_name: &str,
    address: Ipv4Addr,
) -> Result<(), BackendError> {
    let address = address.to_string();
    runner.run(
        "ifconfig",
        &[
            interface_name.to_owned(),
            "inet".to_owned(),
            address.clone(),
            address,
            "netmask".to_owned(),
            "255.255.255.255".to_owned(),
        ],
    )
}

fn cleanup_macos_utun(
    runner: &mut dyn WireguardCommandRunner,
    interface_name: &str,
) -> Result<(), BackendError> {
    match runner.run("ifconfig", &[interface_name.to_owned(), "down".to_owned()]) {
        Ok(()) => Ok(()),
        Err(err) if is_missing_interface_error(&err) => Ok(()),
        Err(err) => Err(err),
    }
}

fn is_missing_interface_error(err: &BackendError) -> bool {
    let message = err.message.to_ascii_lowercase();
    message.contains("does not exist")
        || message.contains("no such interface")
        || message.contains("interface not found")
        || message.contains("no such device")
}

fn reconcile_macos_backend_routes(
    runner: &mut dyn WireguardCommandRunner,
    interface_name: &str,
    previous_routes: &[Route],
    next_routes: &[Route],
) -> Result<(), BackendError> {
    validate_macos_utun_name(interface_name)?;
    let previous_programmed = backend_programmed_route_cidrs(previous_routes)?;
    let next_programmed = backend_programmed_route_cidrs(next_routes)?;

    let forward_result = apply_macos_backend_route_plan(
        runner,
        interface_name,
        &previous_programmed,
        &next_programmed,
    );
    match forward_result {
        Ok(()) => Ok(()),
        Err(err) => {
            let rollback_result = apply_macos_backend_route_plan(
                runner,
                interface_name,
                &next_programmed,
                &previous_programmed,
            );
            match rollback_result {
                Ok(()) => Err(err),
                Err(rollback_err) => Err(combine_route_reconciliation_error(err, rollback_err)),
            }
        }
    }
}

fn apply_macos_backend_route_plan(
    runner: &mut dyn WireguardCommandRunner,
    interface_name: &str,
    previous_programmed: &[ParsedRouteCidr],
    next_programmed: &[ParsedRouteCidr],
) -> Result<(), BackendError> {
    for cidr in next_programmed {
        if previous_programmed.iter().any(|previous| previous == cidr) {
            continue;
        }
        let args = macos_route_add_args(cidr, interface_name);
        runner.run("route", &args)?;
    }

    for cidr in previous_programmed {
        if next_programmed.iter().any(|next| next == cidr) {
            continue;
        }
        let args = macos_route_delete_args(cidr);
        match runner.run("route", &args) {
            Ok(()) => {}
            Err(err) if is_missing_route_error(&err) => {}
            Err(err) => return Err(err),
        }
    }

    Ok(())
}

fn backend_programmed_route_cidrs(routes: &[Route]) -> Result<Vec<ParsedRouteCidr>, BackendError> {
    routes
        .iter()
        .filter(|route| !matches!(route.kind, RouteKind::ExitNodeDefault))
        .map(|route| ParsedRouteCidr::parse(&route.destination_cidr))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRouteCidr {
    address: IpAddr,
    prefix_len: u8,
}

impl ParsedRouteCidr {
    fn parse(value: &str) -> Result<Self, BackendError> {
        let (address, prefix_len) = value
            .split_once('/')
            .ok_or_else(|| BackendError::invalid_input("invalid cidr value"))?;
        if address.is_empty() || prefix_len.is_empty() || prefix_len.contains('/') {
            return Err(BackendError::invalid_input("invalid cidr value"));
        }
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| BackendError::invalid_input("invalid cidr address"))?;
        let prefix_len = prefix_len
            .parse::<u8>()
            .map_err(|_| BackendError::invalid_input("invalid cidr prefix"))?;
        match address {
            IpAddr::V4(_) if prefix_len <= 32 => {}
            IpAddr::V4(_) => return Err(BackendError::invalid_input("invalid ipv4 prefix")),
            IpAddr::V6(_) if prefix_len <= 128 => {}
            IpAddr::V6(_) => return Err(BackendError::invalid_input("invalid ipv6 prefix")),
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }

    fn family_arg(&self) -> String {
        if self.address.is_ipv6() {
            "-inet6".to_owned()
        } else {
            "-inet".to_owned()
        }
    }

    fn route_arg(&self) -> String {
        format!("{}/{}", self.address, self.prefix_len)
    }
}

fn macos_route_add_args(cidr: &ParsedRouteCidr, interface_name: &str) -> Vec<String> {
    vec![
        "-n".to_owned(),
        "add".to_owned(),
        cidr.family_arg(),
        "-net".to_owned(),
        cidr.route_arg(),
        "-interface".to_owned(),
        interface_name.to_owned(),
    ]
}

fn macos_route_delete_args(cidr: &ParsedRouteCidr) -> Vec<String> {
    vec![
        "-n".to_owned(),
        "delete".to_owned(),
        cidr.family_arg(),
        "-net".to_owned(),
        cidr.route_arg(),
    ]
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

fn combine_tun_start_cleanup_error(primary: BackendError, cleanup: BackendError) -> BackendError {
    BackendError::internal(format!(
        "{}; cleanup failed: {}",
        primary.message, cleanup.message
    ))
}

fn combine_macos_cleanup_error(primary: BackendError, cleanup: BackendError) -> BackendError {
    BackendError::internal(format!(
        "{}; interface cleanup failed: {}",
        primary.message, cleanup.message
    ))
}

fn is_missing_route_error(err: &BackendError) -> bool {
    let message = err.message.to_ascii_lowercase();
    message.contains("not in table") || message.contains("no such process")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MacosDefaultRoute {
    gateway: Ipv4Addr,
    interface_name: String,
}

fn reconcile_macos_exit_mode(
    runner: &mut dyn WireguardCommandRunner,
    interface_name: &str,
    previous_mode: ExitMode,
    next_mode: ExitMode,
    peers: &[PeerConfig],
    default_route: &mut Option<MacosDefaultRoute>,
    endpoint_bypass_hosts: &mut BTreeSet<IpAddr>,
) -> Result<(), BackendError> {
    validate_macos_utun_name(interface_name)?;
    let forward_result = apply_macos_exit_mode_plan(
        runner,
        interface_name,
        next_mode,
        peers,
        default_route,
        endpoint_bypass_hosts,
    );
    match forward_result {
        Ok(()) => Ok(()),
        Err(err) => {
            let rollback_result = apply_macos_exit_mode_plan(
                runner,
                interface_name,
                previous_mode,
                peers,
                default_route,
                endpoint_bypass_hosts,
            );
            match rollback_result {
                Ok(()) => Err(err),
                Err(rollback_err) => Err(combine_exit_mode_reconciliation_error(err, rollback_err)),
            }
        }
    }
}

fn apply_macos_exit_mode_plan(
    runner: &mut dyn WireguardCommandRunner,
    interface_name: &str,
    mode: ExitMode,
    peers: &[PeerConfig],
    default_route: &mut Option<MacosDefaultRoute>,
    endpoint_bypass_hosts: &mut BTreeSet<IpAddr>,
) -> Result<(), BackendError> {
    match mode {
        ExitMode::Off => restore_macos_default_route(runner, default_route, endpoint_bypass_hosts),
        ExitMode::FullTunnel => {
            let previous_default_route = default_route.clone();
            let previous_endpoint_bypass_hosts = endpoint_bypass_hosts.clone();
            let captured = match default_route.clone() {
                Some(route) => route,
                None => capture_macos_default_route(runner)?,
            };
            if let Err(err) = install_macos_endpoint_bypass_routes(
                runner,
                &captured,
                peers,
                endpoint_bypass_hosts,
            ) {
                *default_route = previous_default_route;
                *endpoint_bypass_hosts = previous_endpoint_bypass_hosts;
                return Err(err);
            }
            if let Err(err) = change_macos_default_route_to_tunnel(runner, interface_name) {
                let cleanup_result =
                    remove_macos_endpoint_bypass_routes(runner, endpoint_bypass_hosts);
                if cleanup_result.is_ok() {
                    *default_route = previous_default_route;
                    *endpoint_bypass_hosts = previous_endpoint_bypass_hosts;
                }
                return match cleanup_result {
                    Ok(()) => Err(err),
                    Err(cleanup_err) => {
                        Err(combine_endpoint_bypass_cleanup_error(err, cleanup_err))
                    }
                };
            }
            *default_route = Some(captured);
            Ok(())
        }
    }
}

fn capture_macos_default_route(
    runner: &mut dyn WireguardCommandRunner,
) -> Result<MacosDefaultRoute, BackendError> {
    let output = runner.run_capture(
        "route",
        &["-n".to_owned(), "get".to_owned(), "default".to_owned()],
    )?;
    parse_macos_default_route_output(&output)
}

fn parse_macos_default_route_output(
    output: &WireguardCommandOutput,
) -> Result<MacosDefaultRoute, BackendError> {
    let mut gateway = None;
    let mut interface_name = None;
    for line in output.stdout.lines() {
        let normalized = line.trim();
        if let Some(value) = normalized.strip_prefix("gateway:") {
            let value = value.trim();
            if !value.is_empty() {
                gateway = Some(value.parse::<Ipv4Addr>().map_err(|_| {
                    BackendError::internal("default route gateway is not a valid IPv4 address")
                })?);
            }
        }
        if let Some(value) = normalized.strip_prefix("interface:") {
            let value = value.trim();
            if !value.is_empty() {
                validate_interface_name(value)?;
                interface_name = Some(value.to_owned());
            }
        }
    }
    Ok(MacosDefaultRoute {
        gateway: gateway
            .ok_or_else(|| BackendError::internal("default gateway not found in route output"))?,
        interface_name: interface_name.ok_or_else(|| {
            BackendError::internal("default route interface not found in route output")
        })?,
    })
}

fn install_macos_endpoint_bypass_routes(
    runner: &mut dyn WireguardCommandRunner,
    default_route: &MacosDefaultRoute,
    peers: &[PeerConfig],
    endpoint_bypass_hosts: &mut BTreeSet<IpAddr>,
) -> Result<(), BackendError> {
    let previous_hosts = endpoint_bypass_hosts.clone();
    let next_hosts: BTreeSet<IpAddr> = peers.iter().map(|peer| peer.endpoint.addr).collect();
    if let Err(err) =
        apply_macos_endpoint_bypass_delta(runner, default_route, endpoint_bypass_hosts, &next_hosts)
    {
        let rollback_result = apply_macos_endpoint_bypass_delta(
            runner,
            default_route,
            endpoint_bypass_hosts,
            &previous_hosts,
        );
        return match rollback_result {
            Ok(()) => {
                *endpoint_bypass_hosts = previous_hosts;
                Err(err)
            }
            Err(rollback_err) => Err(combine_endpoint_bypass_reconciliation_error(
                err,
                rollback_err,
            )),
        };
    }
    Ok(())
}

fn apply_macos_endpoint_bypass_delta(
    runner: &mut dyn WireguardCommandRunner,
    default_route: &MacosDefaultRoute,
    endpoint_bypass_hosts: &mut BTreeSet<IpAddr>,
    next_hosts: &BTreeSet<IpAddr>,
) -> Result<(), BackendError> {
    for endpoint in endpoint_bypass_hosts.clone() {
        if !next_hosts.contains(&endpoint) {
            remove_macos_endpoint_bypass_route(runner, endpoint)?;
            endpoint_bypass_hosts.remove(&endpoint);
        }
    }
    for endpoint in next_hosts {
        if endpoint_bypass_hosts.contains(endpoint) {
            continue;
        }
        if !macos_endpoint_needs_gateway_bypass(runner, *endpoint)? {
            // On-link (same-subnet) peer endpoint: the intact connected route
            // already reaches it directly on the physical interface. A
            // /32-via-gateway bypass would be MORE specific than the connected
            // route and shadow it, sending the underlay to the LAN gateway —
            // which cannot hairpin a same-subnet destination, so the WireGuard
            // underlay would never arrive. Skip it; the connected route handles
            // this peer. (Under the wg-quick split-default the connected LAN /24
            // stays intact, so same-subnet peers need no bypass at all.)
            continue;
        }
        add_macos_endpoint_bypass_route(runner, default_route, *endpoint)?;
        endpoint_bypass_hosts.insert(*endpoint);
    }
    Ok(())
}

/// Whether a peer underlay endpoint needs a `/32`-via-gateway bypass under the
/// wg-quick split-default. Only OFF-subnet endpoints (reachable via the default
/// gateway, hence captured by the `0.0.0.0/1`+`128.0.0.0/1` tunnel halves) need
/// one; an on-link (same-subnet) endpoint is delivered directly by the intact
/// connected route, and a via-gateway bypass would actively break it. Decided
/// from the pre-enforce routing table: a `gateway:` line in `route -n get`
/// output means the endpoint is reached via a gateway (off-subnet). On any query
/// failure, default to NOT needing a bypass (skip) — the safe choice for the
/// common same-subnet topology, since a wrongly-added gateway bypass breaks the
/// underlay whereas a missing one merely leaves a genuinely off-subnet peer to
/// the tunnel halves.
fn macos_endpoint_needs_gateway_bypass(
    runner: &mut dyn WireguardCommandRunner,
    endpoint: IpAddr,
) -> Result<bool, BackendError> {
    match runner.run_capture(
        "route",
        &[
            "-n".to_owned(),
            "get".to_owned(),
            macos_route_family_arg(endpoint),
            endpoint.to_string(),
        ],
    ) {
        Ok(output) => Ok(output
            .stdout
            .lines()
            .any(|line| line.trim().starts_with("gateway:"))),
        Err(_) => Ok(false),
    }
}

fn add_macos_endpoint_bypass_route(
    runner: &mut dyn WireguardCommandRunner,
    default_route: &MacosDefaultRoute,
    endpoint: IpAddr,
) -> Result<(), BackendError> {
    // Plain `route add -host <ep> <gw>` (no `-ifscope`). An ifscope'd
    // route on macOS is only consulted for sockets that have explicitly
    // bound to the named interface; the daemon's WireGuard authoritative
    // UDP socket is bound to 0.0.0.0:51820, so under `-ifscope en0` the
    // route lookup falls through to the default route — and after the
    // daemon retargets the default route to the utun for full-tunnel
    // exit mode, the encrypted WireGuard handshake packets to the peer
    // endpoint loop back into the tunnel they are meant to bring up.
    // Without `-ifscope` the host route is installed at the default
    // (non-scoped) flavor, so unbound sockets see it and the
    // handshake leaves via en0 toward the LAN gateway as intended.
    runner.run(
        "route",
        &[
            "-n".to_owned(),
            "add".to_owned(),
            macos_route_family_arg(endpoint),
            "-host".to_owned(),
            endpoint.to_string(),
            default_route.gateway.to_string(),
        ],
    )
}

fn remove_macos_endpoint_bypass_route(
    runner: &mut dyn WireguardCommandRunner,
    endpoint: IpAddr,
) -> Result<(), BackendError> {
    match runner.run(
        "route",
        &[
            "-n".to_owned(),
            "delete".to_owned(),
            macos_route_family_arg(endpoint),
            "-host".to_owned(),
            endpoint.to_string(),
        ],
    ) {
        Ok(()) => Ok(()),
        Err(err) if is_missing_route_error(&err) => Ok(()),
        Err(err) => Err(err),
    }
}

fn remove_macos_endpoint_bypass_routes(
    runner: &mut dyn WireguardCommandRunner,
    endpoint_bypass_hosts: &mut BTreeSet<IpAddr>,
) -> Result<(), BackendError> {
    let mut first_error = None;
    for endpoint in endpoint_bypass_hosts.clone() {
        match remove_macos_endpoint_bypass_route(runner, endpoint) {
            Ok(()) => {
                endpoint_bypass_hosts.remove(&endpoint);
            }
            Err(err) if first_error.is_none() => {
                first_error = Some(err);
            }
            Err(_) => {}
        }
    }
    match first_error {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// The two halves that together cover all of `0.0.0.0/0` while remaining MORE
/// specific than the system `default` route (the standard wg-quick trick).
const MACOS_SPLIT_DEFAULT_HALVES: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];

fn change_macos_default_route_to_tunnel(
    runner: &mut dyn WireguardCommandRunner,
    interface_name: &str,
) -> Result<(), BackendError> {
    // wg-quick split-default: route ALL of 0.0.0.0/0 through the tunnel via the
    // two halves 0.0.0.0/1 + 128.0.0.0/1 instead of repointing `default`.
    //
    // Why not `route change default -interface utun`: repointing the system
    // default at the utun makes the utun the PRIMARY interface, so macOS source
    // address selection picks the utun's address as the source for
    // LAN-destined packets and the strong-host / scoped-routing check then drops
    // them, so the WireGuard underlay cannot reach a same-subnet peer's
    // endpoint. The /1 halves keep `default` AND the connected LAN /24 intact,
    // so the physical interface stays primary and the underlay egresses it with
    // the correct source, while every internet address still matches a /1 half
    // and is fully tunneled — the killswitch posture is preserved (fail-closed:
    // if the utun drops, the /1 routes blackhole the traffic rather than leaking
    // it onto the physical link).
    for half in MACOS_SPLIT_DEFAULT_HALVES {
        let add_args = vec![
            "-n".to_owned(),
            "add".to_owned(),
            "-inet".to_owned(),
            "-net".to_owned(),
            half.to_owned(),
            "-interface".to_owned(),
            interface_name.to_owned(),
        ];
        if runner.run("route", &add_args).is_err() {
            // Already present from a prior partial apply — converge it.
            runner.run(
                "route",
                &[
                    "-n".to_owned(),
                    "change".to_owned(),
                    "-inet".to_owned(),
                    "-net".to_owned(),
                    half.to_owned(),
                    "-interface".to_owned(),
                    interface_name.to_owned(),
                ],
            )?;
        }
    }
    Ok(())
}

fn restore_macos_default_route(
    runner: &mut dyn WireguardCommandRunner,
    default_route: &mut Option<MacosDefaultRoute>,
    endpoint_bypass_hosts: &mut BTreeSet<IpAddr>,
) -> Result<(), BackendError> {
    // wg-quick split-default teardown: remove the 0.0.0.0/1 + 128.0.0.0/1 tunnel
    // halves. The system `default` route was never repointed (see
    // change_macos_default_route_to_tunnel), so there is nothing to restore
    // there — just drop the halves and the per-peer bypass routes.
    for half in MACOS_SPLIT_DEFAULT_HALVES {
        match runner.run(
            "route",
            &[
                "-n".to_owned(),
                "delete".to_owned(),
                "-inet".to_owned(),
                "-net".to_owned(),
                half.to_owned(),
            ],
        ) {
            Ok(()) => {}
            Err(err) if is_missing_route_error(&err) => {}
            Err(err) => return Err(err),
        }
    }
    remove_macos_endpoint_bypass_routes(runner, endpoint_bypass_hosts)?;
    *default_route = None;
    Ok(())
}

fn macos_route_family_arg(endpoint: IpAddr) -> String {
    if endpoint.is_ipv6() {
        "-inet6".to_owned()
    } else {
        "-inet".to_owned()
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

fn combine_endpoint_bypass_reconciliation_error(
    primary: BackendError,
    rollback: BackendError,
) -> BackendError {
    BackendError::internal(format!(
        "{}; endpoint bypass rollback failed: {}",
        primary.message, rollback.message
    ))
}

fn combine_endpoint_bypass_cleanup_error(
    primary: BackendError,
    cleanup: BackendError,
) -> BackendError {
    BackendError::internal(format!(
        "{}; endpoint bypass cleanup failed: {}",
        primary.message, cleanup.message
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_command::WireguardCommandOutput;
    use rustynet_backend_api::NodeId;

    fn runtime_context(local_cidr: &str) -> RuntimeContext {
        RuntimeContext {
            local_node: NodeId::new("mac-node").expect("valid node id"),
            interface_name: "utun9".to_owned(),
            mesh_cidr: "100.64.0.0/10".to_owned(),
            local_cidr: local_cidr.to_owned(),
        }
    }

    #[test]
    fn validate_macos_utun_name_accepts_numbered_utun() {
        validate_macos_utun_name("utun9").expect("numbered utun should validate");
    }

    #[test]
    fn validate_macos_utun_name_rejects_non_utun_or_dynamic_name() {
        assert!(validate_macos_utun_name("rustynet0").is_err());
        assert!(validate_macos_utun_name("utun").is_err());
        assert!(validate_macos_utun_name("utunx").is_err());
    }

    #[test]
    fn parsed_local_cidr_accepts_ipv4_prefix() {
        let parsed = ParsedLocalCidr::parse("100.64.0.2/32").expect("valid cidr");
        assert_eq!(parsed.address, Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(parsed.prefix_len, 32);
    }

    #[test]
    fn parsed_local_cidr_rejects_ipv6_until_parity_lands() {
        let err = ParsedLocalCidr::parse("fd00::1/128").expect_err("ipv6 should be rejected");
        assert!(
            err.message
                .contains("currently requires an IPv4 local cidr")
        );
    }

    #[test]
    fn combine_tun_start_cleanup_error_preserves_primary_and_cleanup_failure() {
        let err = combine_tun_start_cleanup_error(
            BackendError::internal("ifconfig address failed"),
            BackendError::internal("cleanup ifconfig down failed"),
        );

        assert_eq!(err.kind, rustynet_backend_api::BackendErrorKind::Internal);
        assert!(err.message.contains("ifconfig address failed"));
        assert!(err.message.contains("cleanup failed"));
        assert!(err.message.contains("cleanup ifconfig down failed"));
    }

    #[test]
    fn test_lifecycle_records_prepare_and_handle_lifetime() {
        let lifecycle = TestMacosTunLifecycle::new();
        let state = lifecycle.state();
        let shared = SharedMacosTunLifecycle::new(Box::new(lifecycle));
        let device = shared
            .prepare_and_open("utun9", &runtime_context("100.64.0.2/32"))
            .expect("test lifecycle should open");
        let snapshot = state.snapshot();
        assert_eq!(snapshot.prepare_calls, 1);
        assert_eq!(snapshot.live_handles, 1);
        assert_eq!(snapshot.last_interface_name.as_deref(), Some("utun9"));
        assert_eq!(snapshot.last_local_cidr.as_deref(), Some("100.64.0.2/32"));
        drop(device);
        assert_eq!(state.snapshot().live_handles, 0);
    }

    #[test]
    fn test_lifecycle_cleanup_records_interface() {
        let lifecycle = TestMacosTunLifecycle::new();
        let state = lifecycle.state();
        let shared = SharedMacosTunLifecycle::new(Box::new(lifecycle));
        shared.cleanup("utun9").expect("cleanup should succeed");
        let snapshot = state.snapshot();
        assert_eq!(snapshot.cleanup_calls, 1);
        assert_eq!(
            snapshot.last_cleanup_interface_name.as_deref(),
            Some("utun9")
        );
    }

    #[test]
    fn test_device_queues_and_records_packets() {
        let state = MacosTunTestState::default();
        state.queue_inbound_packet(vec![1, 2, 3]);
        let device = MacosTunDevice::test_handle(state.clone());
        assert_eq!(
            device.recv_packet().expect("recv should succeed"),
            Some(vec![1, 2, 3])
        );
        device
            .send_packet(&[4, 5, 6])
            .expect("send should record packet");
        assert_eq!(
            state.snapshot().recorded_outbound_packets,
            vec![vec![4, 5, 6]]
        );
    }

    #[test]
    fn test_device_drops_empty_inbound_packets_without_worker_churn() {
        let state = MacosTunTestState::default();
        state.queue_inbound_packet(Vec::new());
        state.queue_inbound_packet(vec![4, 5, 6]);
        let device = MacosTunDevice::test_handle(state);

        assert_eq!(
            device.recv_packet().expect("recv should skip empty packet"),
            Some(vec![4, 5, 6])
        );
        assert_eq!(
            device.recv_packet().expect("empty queue should not fail"),
            None
        );
    }

    #[test]
    fn reconcile_macos_backend_routes_skips_default_and_uses_route_argv() {
        let mut runner = RecordingRunner::default();
        let previous = vec![route("100.64.1.0/24", RouteKind::Mesh)];
        let next = vec![
            route("100.64.2.0/24", RouteKind::Mesh),
            route("0.0.0.0/0", RouteKind::ExitNodeDefault),
        ];

        reconcile_macos_backend_routes(&mut runner, "utun9", &previous, &next)
            .expect("route reconciliation should succeed");

        assert_eq!(
            runner.calls,
            vec![
                vec![
                    "route".to_owned(),
                    "-n".to_owned(),
                    "add".to_owned(),
                    "-inet".to_owned(),
                    "-net".to_owned(),
                    "100.64.2.0/24".to_owned(),
                    "-interface".to_owned(),
                    "utun9".to_owned(),
                ],
                vec![
                    "route".to_owned(),
                    "-n".to_owned(),
                    "delete".to_owned(),
                    "-inet".to_owned(),
                    "-net".to_owned(),
                    "100.64.1.0/24".to_owned(),
                ],
            ]
        );
    }

    #[test]
    fn reconcile_macos_backend_routes_rolls_back_on_add_failure() {
        let mut runner = RecordingRunner {
            fail_on_cidr: Some("100.64.2.0/24".to_owned()),
            ..RecordingRunner::default()
        };
        let previous = vec![route("100.64.1.0/24", RouteKind::Mesh)];
        let next = vec![route("100.64.2.0/24", RouteKind::Mesh)];

        let err = reconcile_macos_backend_routes(&mut runner, "utun9", &previous, &next)
            .expect_err("route add should fail");

        assert!(err.message.contains("scripted route failure"));
        assert!(
            runner.calls.iter().any(|call| call
                == &vec![
                    "route".to_owned(),
                    "-n".to_owned(),
                    "add".to_owned(),
                    "-inet".to_owned(),
                    "-net".to_owned(),
                    "100.64.1.0/24".to_owned(),
                    "-interface".to_owned(),
                    "utun9".to_owned(),
                ]),
            "rollback should re-add previous route, calls: {:?}",
            runner.calls
        );
    }

    #[test]
    fn parsed_route_cidr_rejects_invalid_addresses_and_prefixes() {
        assert!(ParsedRouteCidr::parse("999.64.2.0/24").is_err());
        assert!(ParsedRouteCidr::parse("100.64.2.0/33").is_err());
        assert!(ParsedRouteCidr::parse("fd00::1/129").is_err());
        assert!(ParsedRouteCidr::parse("100.64.2.0/24/extra").is_err());
    }

    #[test]
    fn macos_missing_route_detector_does_not_hide_route_tool_failures() {
        assert!(is_missing_route_error(&BackendError::internal(
            "route: writing to routing socket: not in table"
        )));
        assert!(is_missing_route_error(&BackendError::internal(
            "route exited with status 1: writing to routing socket: No such process"
        )));
        assert!(!is_missing_route_error(&BackendError::internal(
            "route spawn failed: No such file or directory"
        )));
    }

    #[test]
    fn reconcile_macos_backend_routes_rejects_invalid_cidr_without_route_calls() {
        let mut runner = RecordingRunner::default();
        let previous = vec![route("100.64.1.0/24", RouteKind::Mesh)];
        let next = vec![route("999.64.2.0/24", RouteKind::Mesh)];

        let err = reconcile_macos_backend_routes(&mut runner, "utun9", &previous, &next)
            .expect_err("invalid route cidr should fail before route command");

        assert!(err.message.contains("invalid cidr address"));
        assert!(runner.calls.is_empty());
    }

    #[test]
    fn reconcile_macos_backend_routes_uses_ipv6_route_family() {
        let mut runner = RecordingRunner::default();
        let previous = Vec::new();
        let next = vec![route("fd00::/64", RouteKind::Mesh)];

        reconcile_macos_backend_routes(&mut runner, "utun9", &previous, &next)
            .expect("ipv6 route reconciliation should succeed");

        assert_eq!(
            runner.calls,
            vec![vec![
                "route".to_owned(),
                "-n".to_owned(),
                "add".to_owned(),
                "-inet6".to_owned(),
                "-net".to_owned(),
                "fd00::/64".to_owned(),
                "-interface".to_owned(),
                "utun9".to_owned(),
            ]]
        );
    }

    #[test]
    fn reconcile_macos_exit_mode_full_tunnel_installs_bypass_and_default_route() {
        let mut runner = RecordingRunner {
            capture_stdout: "   gateway: 192.0.2.1\n interface: en0\n".to_owned(),
            ..RecordingRunner::default()
        };
        let peers = vec![peer("peer-a", "203.0.113.10")];
        let mut default_route = None;
        let mut endpoint_bypass_hosts = BTreeSet::new();

        reconcile_macos_exit_mode(
            &mut runner,
            "utun9",
            ExitMode::Off,
            ExitMode::FullTunnel,
            &peers,
            &mut default_route,
            &mut endpoint_bypass_hosts,
        )
        .expect("full tunnel should program");

        assert_eq!(
            runner.calls,
            vec![
                vec![
                    "route".to_owned(),
                    "-n".to_owned(),
                    "get".to_owned(),
                    "default".to_owned(),
                ],
                vec![
                    "route".to_owned(),
                    "-n".to_owned(),
                    "get".to_owned(),
                    "-inet".to_owned(),
                    "203.0.113.10".to_owned(),
                ],
                vec![
                    "route".to_owned(),
                    "-n".to_owned(),
                    "add".to_owned(),
                    "-inet".to_owned(),
                    "-host".to_owned(),
                    "203.0.113.10".to_owned(),
                    "192.0.2.1".to_owned(),
                ],
                vec![
                    "route".to_owned(),
                    "-n".to_owned(),
                    "add".to_owned(),
                    "-inet".to_owned(),
                    "-net".to_owned(),
                    "0.0.0.0/1".to_owned(),
                    "-interface".to_owned(),
                    "utun9".to_owned(),
                ],
                vec![
                    "route".to_owned(),
                    "-n".to_owned(),
                    "add".to_owned(),
                    "-inet".to_owned(),
                    "-net".to_owned(),
                    "128.0.0.0/1".to_owned(),
                    "-interface".to_owned(),
                    "utun9".to_owned(),
                ],
            ]
        );
        assert_eq!(endpoint_bypass_hosts.len(), 1);
        assert_eq!(
            default_route,
            Some(MacosDefaultRoute {
                gateway: Ipv4Addr::new(192, 0, 2, 1),
                interface_name: "en0".to_owned(),
            })
        );
    }

    #[test]
    fn parse_macos_default_route_output_rejects_non_ipv4_gateway() {
        let output = WireguardCommandOutput {
            stdout: "gateway: 192.0.2.1; route delete default\ninterface: en0\n".to_owned(),
            stderr: String::new(),
        };

        let err = parse_macos_default_route_output(&output)
            .expect_err("default route gateway must be a typed IPv4 address");

        assert!(err.message.contains("not a valid IPv4 address"));
    }

    #[test]
    fn reconcile_macos_exit_mode_off_restores_default_and_removes_bypass() {
        let mut runner = RecordingRunner::default();
        let mut default_route = Some(MacosDefaultRoute {
            gateway: Ipv4Addr::new(192, 0, 2, 1),
            interface_name: "en0".to_owned(),
        });
        let mut endpoint_bypass_hosts = BTreeSet::from(["203.0.113.10".parse().expect("ip")]);

        reconcile_macos_exit_mode(
            &mut runner,
            "utun9",
            ExitMode::FullTunnel,
            ExitMode::Off,
            &[],
            &mut default_route,
            &mut endpoint_bypass_hosts,
        )
        .expect("full tunnel off should restore");

        assert_eq!(
            runner.calls,
            vec![
                vec![
                    "route".to_owned(),
                    "-n".to_owned(),
                    "delete".to_owned(),
                    "-inet".to_owned(),
                    "-net".to_owned(),
                    "0.0.0.0/1".to_owned(),
                ],
                vec![
                    "route".to_owned(),
                    "-n".to_owned(),
                    "delete".to_owned(),
                    "-inet".to_owned(),
                    "-net".to_owned(),
                    "128.0.0.0/1".to_owned(),
                ],
                vec![
                    "route".to_owned(),
                    "-n".to_owned(),
                    "delete".to_owned(),
                    "-inet".to_owned(),
                    "-host".to_owned(),
                    "203.0.113.10".to_owned(),
                ],
            ]
        );
        assert!(default_route.is_none());
        assert!(endpoint_bypass_hosts.is_empty());
    }

    #[test]
    fn restore_macos_default_route_preserves_state_when_split_default_delete_fails() {
        let mut runner = RecordingRunner {
            fail_on_cidr: Some("0.0.0.0/1".to_owned()),
            ..RecordingRunner::default()
        };
        let mut default_route = Some(MacosDefaultRoute {
            gateway: Ipv4Addr::new(192, 0, 2, 1),
            interface_name: "en0".to_owned(),
        });
        let mut endpoint_bypass_hosts = BTreeSet::from(["203.0.113.10".parse().expect("ip")]);

        let err = restore_macos_default_route(
            &mut runner,
            &mut default_route,
            &mut endpoint_bypass_hosts,
        )
        .expect_err("default route restore should fail");

        assert!(err.message.contains("scripted route failure"));
        assert_eq!(
            default_route,
            Some(MacosDefaultRoute {
                gateway: Ipv4Addr::new(192, 0, 2, 1),
                interface_name: "en0".to_owned(),
            })
        );
        assert_eq!(
            endpoint_bypass_hosts,
            BTreeSet::from(["203.0.113.10".parse().expect("ip")])
        );
    }

    #[test]
    fn restore_macos_default_route_preserves_failed_bypass_for_retry() {
        let mut runner = RecordingRunner {
            fail_on_cidr: Some("203.0.113.10".to_owned()),
            ..RecordingRunner::default()
        };
        let mut default_route = Some(MacosDefaultRoute {
            gateway: Ipv4Addr::new(192, 0, 2, 1),
            interface_name: "en0".to_owned(),
        });
        let mut endpoint_bypass_hosts = BTreeSet::from([
            "203.0.113.10".parse().expect("ip"),
            "203.0.113.11".parse().expect("ip"),
        ]);

        let err = restore_macos_default_route(
            &mut runner,
            &mut default_route,
            &mut endpoint_bypass_hosts,
        )
        .expect_err("bypass route removal should fail");

        assert!(err.message.contains("scripted route failure"));
        assert_eq!(
            default_route,
            Some(MacosDefaultRoute {
                gateway: Ipv4Addr::new(192, 0, 2, 1),
                interface_name: "en0".to_owned(),
            })
        );
        assert_eq!(
            endpoint_bypass_hosts,
            BTreeSet::from(["203.0.113.10".parse().expect("ip")])
        );
    }

    #[test]
    fn cleanup_macos_runtime_state_attempts_interface_down_when_route_restore_fails() {
        let mut runner = CleanupFailureRunner {
            fail_default_restore: true,
            ..CleanupFailureRunner::default()
        };
        let mut default_route = Some(MacosDefaultRoute {
            gateway: Ipv4Addr::new(192, 0, 2, 1),
            interface_name: "en0".to_owned(),
        });
        let mut endpoint_bypass_hosts = BTreeSet::new();

        let err = cleanup_macos_runtime_state(
            &mut runner,
            &mut default_route,
            &mut endpoint_bypass_hosts,
            "utun9",
        )
        .expect_err("route restore should fail");

        assert!(err.message.contains("default restore failed"));
        assert!(runner.calls.iter().any(|call| {
            call == &vec!["ifconfig".to_owned(), "utun9".to_owned(), "down".to_owned()]
        }));
        assert_eq!(
            default_route,
            Some(MacosDefaultRoute {
                gateway: Ipv4Addr::new(192, 0, 2, 1),
                interface_name: "en0".to_owned(),
            })
        );
    }

    #[test]
    fn cleanup_macos_runtime_state_reports_interface_down_failure_after_route_restore_success() {
        let mut runner = CleanupFailureRunner {
            fail_ifconfig_down: true,
            ..CleanupFailureRunner::default()
        };
        let mut default_route = Some(MacosDefaultRoute {
            gateway: Ipv4Addr::new(192, 0, 2, 1),
            interface_name: "en0".to_owned(),
        });
        let mut endpoint_bypass_hosts = BTreeSet::new();

        let err = cleanup_macos_runtime_state(
            &mut runner,
            &mut default_route,
            &mut endpoint_bypass_hosts,
            "utun9",
        )
        .expect_err("interface down should fail");

        assert!(err.message.contains("ifconfig down failed"));
        assert!(default_route.is_none());
    }

    #[test]
    fn cleanup_macos_runtime_state_combines_route_restore_and_interface_down_failures() {
        let mut runner = CleanupFailureRunner {
            fail_default_restore: true,
            fail_ifconfig_down: true,
            ..CleanupFailureRunner::default()
        };
        let mut default_route = Some(MacosDefaultRoute {
            gateway: Ipv4Addr::new(192, 0, 2, 1),
            interface_name: "en0".to_owned(),
        });
        let mut endpoint_bypass_hosts = BTreeSet::new();

        let err = cleanup_macos_runtime_state(
            &mut runner,
            &mut default_route,
            &mut endpoint_bypass_hosts,
            "utun9",
        )
        .expect_err("both cleanup steps should fail");

        assert!(err.message.contains("default restore failed"));
        assert!(err.message.contains("interface cleanup failed"));
        assert!(err.message.contains("ifconfig down failed"));
    }

    #[test]
    fn install_macos_endpoint_bypass_routes_rolls_back_on_add_failure() {
        let mut runner = RecordingRunner {
            fail_on_cidr: Some("203.0.113.11".to_owned()),
            capture_stdout: "gateway: 192.0.2.1\ninterface: en0\n".to_owned(),
            ..RecordingRunner::default()
        };
        let default_route = MacosDefaultRoute {
            gateway: Ipv4Addr::new(192, 0, 2, 1),
            interface_name: "en0".to_owned(),
        };
        let peers = vec![peer("peer-a", "203.0.113.11")];
        let mut endpoint_bypass_hosts = BTreeSet::from(["203.0.113.10".parse().expect("ip")]);

        let err = install_macos_endpoint_bypass_routes(
            &mut runner,
            &default_route,
            &peers,
            &mut endpoint_bypass_hosts,
        )
        .expect_err("bypass add failure should roll back stale-host deletion");

        assert!(err.message.contains("scripted route failure"));
        assert_eq!(
            endpoint_bypass_hosts,
            BTreeSet::from(["203.0.113.10".parse().expect("ip")])
        );
        assert!(
            runner.calls.iter().any(|call| call
                == &vec![
                    "route".to_owned(),
                    "-n".to_owned(),
                    "add".to_owned(),
                    "-inet".to_owned(),
                    "-host".to_owned(),
                    "203.0.113.10".to_owned(),
                    "192.0.2.1".to_owned(),
                ]),
            "rollback should re-add removed previous bypass host; calls: {:?}",
            runner.calls
        );
    }

    #[test]
    fn reconcile_macos_exit_mode_full_tunnel_reports_bypass_cleanup_failure() {
        let mut runner = DefaultRouteChangeAndBypassCleanupFailureRunner::default();
        let peers = vec![peer("peer-a", "203.0.113.10")];
        let mut default_route = None;
        let mut endpoint_bypass_hosts = BTreeSet::new();

        let err = reconcile_macos_exit_mode(
            &mut runner,
            "utun9",
            ExitMode::Off,
            ExitMode::FullTunnel,
            &peers,
            &mut default_route,
            &mut endpoint_bypass_hosts,
        )
        .expect_err("cleanup failure after default-route failure must be reported");

        assert!(err.message.contains("default route change failed"));
        assert!(err.message.contains("endpoint bypass cleanup failed"));
        assert!(err.message.contains("bypass delete failed"));
        assert!(default_route.is_none());
        assert_eq!(
            endpoint_bypass_hosts,
            BTreeSet::from(["203.0.113.10".parse().expect("ip")])
        );
    }

    fn route(cidr: &str, kind: RouteKind) -> Route {
        Route {
            destination_cidr: cidr.to_owned(),
            via_node: NodeId::new("peer-a").expect("valid node id"),
            kind,
        }
    }

    fn peer(name: &str, endpoint: &str) -> PeerConfig {
        PeerConfig {
            node_id: NodeId::new(name).expect("valid node id"),
            endpoint: SocketEndpoint {
                addr: endpoint.parse().expect("valid endpoint ip"),
                port: 51820,
            },
            public_key: [7; 32],
            allowed_ips: vec!["100.64.1.0/24".to_owned()],
        }
    }

    #[derive(Debug, Default)]
    struct RecordingRunner {
        calls: Vec<Vec<String>>,
        fail_on_cidr: Option<String>,
        capture_stdout: String,
    }

    impl WireguardCommandRunner for RecordingRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            let mut call = Vec::with_capacity(args.len() + 1);
            call.push(program.to_owned());
            call.extend(args.iter().cloned());
            self.calls.push(call);
            if let Some(cidr) = self.fail_on_cidr.as_deref()
                && args.iter().any(|arg| arg == cidr)
            {
                self.fail_on_cidr = None;
                return Err(BackendError::internal("scripted route failure"));
            }
            Ok(())
        }

        fn run_capture(
            &mut self,
            program: &str,
            args: &[String],
        ) -> Result<WireguardCommandOutput, BackendError> {
            let mut call = Vec::with_capacity(args.len() + 1);
            call.push(program.to_owned());
            call.extend(args.iter().cloned());
            self.calls.push(call);
            Ok(WireguardCommandOutput {
                stdout: self.capture_stdout.clone(),
                stderr: String::new(),
            })
        }
    }

    #[derive(Debug, Default)]
    struct CleanupFailureRunner {
        calls: Vec<Vec<String>>,
        fail_default_restore: bool,
        fail_ifconfig_down: bool,
    }

    impl WireguardCommandRunner for CleanupFailureRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            let mut call = Vec::with_capacity(args.len() + 1);
            call.push(program.to_owned());
            call.extend(args.iter().cloned());
            self.calls.push(call);

            let default_restore = program == "route"
                && args.get(1).map(String::as_str) == Some("delete")
                && args.iter().any(|arg| arg == "0.0.0.0/1");
            if self.fail_default_restore && default_restore {
                return Err(BackendError::internal("default restore failed"));
            }

            let interface_down = program == "ifconfig"
                && args.first().map(String::as_str) == Some("utun9")
                && args.get(1).map(String::as_str) == Some("down");
            if self.fail_ifconfig_down && interface_down {
                return Err(BackendError::internal("ifconfig down failed"));
            }

            Ok(())
        }

        fn run_capture(
            &mut self,
            program: &str,
            args: &[String],
        ) -> Result<WireguardCommandOutput, BackendError> {
            let mut call = Vec::with_capacity(args.len() + 1);
            call.push(program.to_owned());
            call.extend(args.iter().cloned());
            self.calls.push(call);
            Ok(WireguardCommandOutput {
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    #[derive(Debug)]
    struct DefaultRouteChangeAndBypassCleanupFailureRunner {
        calls: Vec<Vec<String>>,
        capture_stdout: String,
    }

    impl Default for DefaultRouteChangeAndBypassCleanupFailureRunner {
        fn default() -> Self {
            Self {
                calls: Vec::new(),
                capture_stdout: "gateway: 192.0.2.1\ninterface: en0\n".to_owned(),
            }
        }
    }

    impl WireguardCommandRunner for DefaultRouteChangeAndBypassCleanupFailureRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            let mut call = Vec::with_capacity(args.len() + 1);
            call.push(program.to_owned());
            call.extend(args.iter().cloned());
            self.calls.push(call);

            let default_route_to_tunnel = program == "route"
                && matches!(
                    args.get(1).map(String::as_str),
                    Some("add") | Some("change")
                )
                && args.iter().any(|arg| arg == "0.0.0.0/1")
                && args.iter().any(|arg| arg == "-interface")
                && args.iter().any(|arg| arg == "utun9");
            if default_route_to_tunnel {
                return Err(BackendError::internal("default route change failed"));
            }

            let endpoint_bypass_delete = program == "route"
                && args.get(1).map(String::as_str) == Some("delete")
                && args.iter().any(|arg| arg == "203.0.113.10");
            if endpoint_bypass_delete {
                return Err(BackendError::internal("bypass delete failed"));
            }

            Ok(())
        }

        fn run_capture(
            &mut self,
            program: &str,
            args: &[String],
        ) -> Result<WireguardCommandOutput, BackendError> {
            let mut call = Vec::with_capacity(args.len() + 1);
            call.push(program.to_owned());
            call.extend(args.iter().cloned());
            self.calls.push(call);
            Ok(WireguardCommandOutput {
                stdout: self.capture_stdout.clone(),
                stderr: String::new(),
            })
        }
    }
}
