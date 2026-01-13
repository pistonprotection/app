//! Control Plane Client
//!
//! Manages the gRPC connection to the gateway/control plane service.
//! Handles worker registration, heartbeats, configuration streaming,
//! metrics reporting, and automatic reconnection.

use crate::config_sync::ConfigSyncManager;
use crate::ebpf::{interface::NetworkInterface, loader::EbpfLoader};
use parking_lot::RwLock;
use pistonprotection_common::error::{Error, Result};
use pistonprotection_proto::worker::{
    BackendMetrics, DeregisterRequest, FilterConfig, GetConfigRequest, HeartbeatRequest,
    InterfaceMetrics, RegisterRequest, ReportAttackRequest, ReportMetricsRequest,
    StreamConfigRequest, Worker, WorkerCapabilities, WorkerStatus,
    worker_service_client::WorkerServiceClient,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, broadcast, watch};
use tokio::time::{interval, sleep, timeout};
use tonic::transport::{Channel, Endpoint};
use tracing::{debug, error, info, warn};

/// Control plane connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected to control plane
    Disconnected,
    /// Attempting to connect
    Connecting,
    /// Connected and registered
    Connected,
    /// Connection lost, attempting to reconnect
    Reconnecting,
    /// Gracefully shutting down
    ShuttingDown,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Disconnected => write!(f, "disconnected"),
            ConnectionState::Connecting => write!(f, "connecting"),
            ConnectionState::Connected => write!(f, "connected"),
            ConnectionState::Reconnecting => write!(f, "reconnecting"),
            ConnectionState::ShuttingDown => write!(f, "shutting_down"),
        }
    }
}

/// Configuration for the control plane client
#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    /// Control plane address (e.g., "http://gateway:50051")
    pub address: String,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
    /// Metrics reporting interval
    pub metrics_interval: Duration,
    /// Maximum reconnection attempts before giving up (0 = infinite)
    pub max_reconnect_attempts: u32,
    /// Initial reconnection delay
    pub reconnect_delay: Duration,
    /// Maximum reconnection delay (for exponential backoff)
    pub max_reconnect_delay: Duration,
    /// Enable configuration streaming
    pub enable_config_stream: bool,
    /// Worker node name (for identification)
    pub node_name: String,
    /// Worker labels
    pub labels: HashMap<String, String>,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            address: "http://gateway:50051".to_string(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(10),
            metrics_interval: Duration::from_secs(30),
            max_reconnect_attempts: 0, // Infinite
            reconnect_delay: Duration::from_secs(1),
            max_reconnect_delay: Duration::from_secs(60),
            enable_config_stream: true,
            node_name: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            labels: HashMap::new(),
        }
    }
}

impl ControlPlaneConfig {
    /// Create from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(addr) = std::env::var("PISTON_CONTROL_PLANE_ADDR") {
            config.address = addr;
        }

        if let Ok(name) = std::env::var("NODE_NAME") {
            config.node_name = name;
        }

        if let Ok(timeout_secs) = std::env::var("PISTON_CONNECT_TIMEOUT") {
            if let Ok(secs) = timeout_secs.parse::<u64>() {
                config.connect_timeout = Duration::from_secs(secs);
            }
        }

        if let Ok(interval_secs) = std::env::var("PISTON_HEARTBEAT_INTERVAL") {
            if let Ok(secs) = interval_secs.parse::<u64>() {
                config.heartbeat_interval = Duration::from_secs(secs);
            }
        }

        if let Ok(interval_secs) = std::env::var("PISTON_METRICS_INTERVAL") {
            if let Ok(secs) = interval_secs.parse::<u64>() {
                config.metrics_interval = Duration::from_secs(secs);
            }
        }

        // Parse labels from PISTON_WORKER_LABELS (format: key1=value1,key2=value2)
        if let Ok(labels_str) = std::env::var("PISTON_WORKER_LABELS") {
            for pair in labels_str.split(',') {
                if let Some((key, value)) = pair.split_once('=') {
                    config
                        .labels
                        .insert(key.trim().to_string(), value.trim().to_string());
                }
            }
        }

        config
    }
}

/// Metrics collected from the worker
#[derive(Debug, Clone, Default)]
pub struct WorkerMetricsSnapshot {
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub interfaces: Vec<InterfaceMetricsSnapshot>,
}

/// Interface-level metrics
#[derive(Debug, Clone, Default)]
pub struct InterfaceMetricsSnapshot {
    pub name: String,
    pub rx_pps: u64,
    pub tx_pps: u64,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub xdp_pass: u64,
    pub xdp_drop: u64,
    pub xdp_redirect: u64,
}

/// Backend-specific metrics for reporting
#[derive(Debug, Clone, Default)]
pub struct BackendMetricsSnapshot {
    pub backend_id: String,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_dropped: u64,
    pub packets_challenged: u64,
    pub drops_by_reason: HashMap<String, u64>,
}

/// Attack information for reporting
#[derive(Debug, Clone)]
pub struct AttackInfo {
    pub backend_id: String,
    pub attack_type: String,
    pub attack_pps: u64,
    pub attack_bps: u64,
    pub sources: Vec<AttackSourceInfo>,
}

/// Attack source information
#[derive(Debug, Clone)]
pub struct AttackSourceInfo {
    pub ip: std::net::IpAddr,
    pub packets: u64,
    pub bytes: u64,
}

/// Control Plane Client
///
/// Manages the connection to the control plane gateway and handles:
/// - Worker registration and deregistration
/// - Periodic heartbeats
/// - Configuration synchronization
/// - Metrics reporting
/// - Attack event reporting
/// - Automatic reconnection with exponential backoff
pub struct ControlPlaneClient {
    /// Configuration
    config: ControlPlaneConfig,
    /// Current connection state
    state: Arc<RwLock<ConnectionState>>,
    /// Assigned worker ID (after registration)
    worker_id: Arc<RwLock<Option<String>>>,
    /// Current configuration version
    config_version: Arc<AtomicU32>,
    /// Network interfaces on this worker
    interfaces: Arc<Vec<NetworkInterface>>,
    /// eBPF loader reference
    loader: Arc<RwLock<EbpfLoader>>,
    /// Configuration sync manager
    config_sync: Arc<ConfigSyncManager>,
    /// gRPC client (wrapped in mutex for exclusive access during reconnection)
    client: Arc<Mutex<Option<WorkerServiceClient<Channel>>>>,
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
    /// State change notification
    state_tx: watch::Sender<ConnectionState>,
    /// State change receiver (cloneable)
    state_rx: watch::Receiver<ConnectionState>,
    /// Reconnection attempt counter
    reconnect_attempts: Arc<AtomicU32>,
    /// Last successful heartbeat timestamp
    last_heartbeat: Arc<AtomicU64>,
    /// Running flag
    running: Arc<AtomicBool>,
}

impl ControlPlaneClient {
    /// Create a new control plane client
    pub fn new(
        config: ControlPlaneConfig,
        interfaces: Vec<NetworkInterface>,
        loader: Arc<RwLock<EbpfLoader>>,
        config_sync: Arc<ConfigSyncManager>,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        let (state_tx, state_rx) = watch::channel(ConnectionState::Disconnected);

        Self {
            config,
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            worker_id: Arc::new(RwLock::new(None)),
            config_version: Arc::new(AtomicU32::new(0)),
            interfaces: Arc::new(interfaces),
            loader,
            config_sync,
            client: Arc::new(Mutex::new(None)),
            shutdown_tx,
            state_tx,
            state_rx,
            reconnect_attempts: Arc::new(AtomicU32::new(0)),
            last_heartbeat: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get the current connection state
    pub fn connection_state(&self) -> ConnectionState {
        *self.state.read()
    }

    /// Get the assigned worker ID
    pub fn worker_id(&self) -> Option<String> {
        self.worker_id.read().clone()
    }

    /// Get the current configuration version
    pub fn config_version(&self) -> u32 {
        self.config_version.load(Ordering::SeqCst)
    }

    /// Subscribe to state changes
    pub fn subscribe_state_changes(&self) -> watch::Receiver<ConnectionState> {
        self.state_rx.clone()
    }

    /// Check if connected to control plane
    pub fn is_connected(&self) -> bool {
        matches!(self.connection_state(), ConnectionState::Connected)
    }

    /// Get time since last successful heartbeat (in seconds)
    pub fn seconds_since_last_heartbeat(&self) -> u64 {
        let last = self.last_heartbeat.load(Ordering::SeqCst);
        if last == 0 {
            return u64::MAX;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(last)
    }

    /// Update internal state and notify subscribers
    fn set_state(&self, new_state: ConnectionState) {
        *self.state.write() = new_state;
        let _ = self.state_tx.send(new_state);
        debug!("Control plane connection state: {}", new_state);
    }

    /// Start the control plane client
    ///
    /// This spawns background tasks for:
    /// - Connection management and reconnection
    /// - Heartbeat loop
    /// - Metrics reporting
    /// - Configuration streaming (if enabled)
    pub async fn start(&self) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(Error::Internal(
                "Control plane client already running".to_string(),
            ));
        }

        info!(
            "Starting control plane client, connecting to {}",
            self.config.address
        );

        // Initial connection
        self.connect_and_register().await?;

        // Spawn heartbeat task
        let _heartbeat_handle = self.spawn_heartbeat_task();

        // Spawn metrics reporting task
        let _metrics_handle = self.spawn_metrics_task();

        // Spawn config streaming task if enabled
        let _config_handle = if self.config.enable_config_stream {
            Some(self.spawn_config_stream_task())
        } else {
            None
        };

        // Spawn reconnection monitor
        let _reconnect_handle = self.spawn_reconnection_task();

        Ok(())
    }

    /// Connect to the control plane and register the worker
    async fn connect_and_register(&self) -> Result<()> {
        self.set_state(ConnectionState::Connecting);

        // Create channel with configuration
        let endpoint = Endpoint::from_shared(self.config.address.clone())
            .map_err(|e| Error::Internal(format!("Invalid control plane address: {}", e)))?
            .connect_timeout(self.config.connect_timeout)
            .timeout(self.config.request_timeout)
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_while_idle(true);

        // Connect with timeout
        let channel = timeout(self.config.connect_timeout, endpoint.connect())
            .await
            .map_err(|_| Error::Internal("Connection timeout".to_string()))?
            .map_err(|e| Error::Internal(format!("Failed to connect: {}", e)))?;

        let mut client = WorkerServiceClient::new(channel);

        // Build worker info
        let worker_info = self.build_worker_info();

        // Register with control plane
        let register_request = RegisterRequest {
            worker: Some(worker_info),
        };

        let response = timeout(
            self.config.request_timeout,
            client.register(register_request),
        )
        .await
        .map_err(|_| Error::Internal("Registration request timeout".to_string()))?
        .map_err(|e| Error::Internal(format!("Registration failed: {}", e)))?;

        let response = response.into_inner();

        // Store worker ID
        *self.worker_id.write() = Some(response.worker_id.clone());

        info!(
            "Registered with control plane, worker_id: {}",
            response.worker_id
        );

        // Apply initial configuration if provided
        if let Some(initial_config) = response.initial_config {
            info!(
                "Received initial configuration version {}",
                initial_config.version
            );
            self.apply_configuration(&initial_config).await?;
        }

        // Store client
        *self.client.lock().await = Some(client);

        // Update state
        self.set_state(ConnectionState::Connected);
        self.reconnect_attempts.store(0, Ordering::SeqCst);
        self.update_last_heartbeat();

        Ok(())
    }

    /// Build worker information for registration
    fn build_worker_info(&self) -> Worker {
        let mut sys = sysinfo::System::new_all();
        sys.refresh_all();

        // Parse kernel version
        let kernel_version = sysinfo::System::kernel_version().unwrap_or_default();
        let (kernel_major, kernel_minor) = parse_kernel_version(&kernel_version);

        Worker {
            id: String::new(), // Assigned by control plane
            node_name: self.config.node_name.clone(),
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            interfaces: self
                .interfaces
                .iter()
                .map(|iface| pistonprotection_proto::worker::NetworkInterface {
                    name: iface.name.clone(),
                    ip_address: iface.ip_address.map(|ip| ip.into()),
                    mac_address: iface
                        .mac_address
                        .map(|mac| {
                            mac.iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .join(":")
                        })
                        .unwrap_or_default(),
                    xdp_status: None,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    rx_packets: 0,
                    tx_packets: 0,
                    rx_dropped: 0,
                    tx_dropped: 0,
                })
                .collect(),
            capabilities: Some(WorkerCapabilities {
                xdp_native: check_xdp_support(XdpSupportLevel::Native),
                xdp_driver: check_xdp_support(XdpSupportLevel::Driver),
                xdp_offload: check_xdp_support(XdpSupportLevel::Offload),
                bpf_helpers: get_available_bpf_helpers(),
                max_bpf_stack_size: 512,
                max_map_entries: 1_000_000,
                cpu_cores: sys.cpus().len() as u32,
                memory_bytes: sys.total_memory(),
                network_drivers: get_network_drivers(&self.interfaces),
                kernel_version,
                kernel_major,
                kernel_minor,
            }),
            status: WorkerStatus::Registering.into(),
            labels: self.config.labels.clone(),
            registered_at: None,
            last_heartbeat: None,
        }
    }

    /// Spawn heartbeat task
    fn spawn_heartbeat_task(&self) -> tokio::task::JoinHandle<()> {
        let client = Arc::clone(&self.client);
        let worker_id = Arc::clone(&self.worker_id);
        let state = Arc::clone(&self.state);
        let config_version = Arc::clone(&self.config_version);
        let last_heartbeat = Arc::clone(&self.last_heartbeat);
        let loader = Arc::clone(&self.loader);
        let interfaces = Arc::clone(&self.interfaces);
        let heartbeat_interval = self.config.heartbeat_interval;
        let request_timeout = self.config.request_timeout;
        let config_sync = Arc::clone(&self.config_sync);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut interval_timer = interval(heartbeat_interval);

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("Heartbeat task shutting down");
                        break;
                    }
                    _ = interval_timer.tick() => {
                        // Skip if not connected
                        if *state.read() != ConnectionState::Connected {
                            continue;
                        }

                        let wid = match worker_id.read().clone() {
                            Some(id) => id,
                            None => continue,
                        };

                        // Collect metrics
                        let metrics = collect_worker_metrics(&loader, &interfaces);

                        let heartbeat = HeartbeatRequest {
                            worker_id: wid.clone(),
                            status: WorkerStatus::Ready.into(),
                            metrics: Some(pistonprotection_proto::worker::WorkerMetrics {
                                cpu_percent: metrics.cpu_percent,
                                memory_percent: metrics.memory_percent,
                                interfaces: metrics
                                    .interfaces
                                    .into_iter()
                                    .map(|i| InterfaceMetrics {
                                        name: i.name,
                                        rx_pps: i.rx_pps,
                                        tx_pps: i.tx_pps,
                                        rx_bps: i.rx_bps,
                                        tx_bps: i.tx_bps,
                                        xdp_pass: i.xdp_pass,
                                        xdp_drop: i.xdp_drop,
                                        xdp_redirect: i.xdp_redirect,
                                    })
                                    .collect(),
                            }),
                        };

                        let mut client_guard = client.lock().await;
                        if let Some(ref mut grpc_client) = *client_guard {
                            match timeout(request_timeout, grpc_client.heartbeat(heartbeat)).await {
                                Ok(Ok(response)) => {
                                    let resp = response.into_inner();

                                    // Update last heartbeat time
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    last_heartbeat.store(now, Ordering::SeqCst);

                                    // Check for config update
                                    if resp.config_update_available {
                                        let current_version = config_version.load(Ordering::SeqCst);
                                        if resp.latest_config_version > current_version {
                                            debug!(
                                                "Configuration update available: {} -> {}",
                                                current_version, resp.latest_config_version
                                            );
                                            // Trigger config fetch (handled by config stream task)
                                            config_sync.trigger_sync();
                                        }
                                    }
                                }
                                Ok(Err(e)) => {
                                    warn!("Heartbeat failed: {}", e);
                                }
                                Err(_) => {
                                    warn!("Heartbeat timeout");
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    /// Spawn metrics reporting task
    fn spawn_metrics_task(&self) -> tokio::task::JoinHandle<()> {
        let client = Arc::clone(&self.client);
        let worker_id = Arc::clone(&self.worker_id);
        let state = Arc::clone(&self.state);
        let loader = Arc::clone(&self.loader);
        let metrics_interval = self.config.metrics_interval;
        let request_timeout = self.config.request_timeout;
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut interval_timer = interval(metrics_interval);

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("Metrics task shutting down");
                        break;
                    }
                    _ = interval_timer.tick() => {
                        // Skip if not connected
                        if *state.read() != ConnectionState::Connected {
                            continue;
                        }

                        let wid = match worker_id.read().clone() {
                            Some(id) => id,
                            None => continue,
                        };

                        // Collect backend metrics
                        let backend_metrics = collect_backend_metrics(&loader);

                        if backend_metrics.is_empty() {
                            continue;
                        }

                        let request = ReportMetricsRequest {
                            worker_id: wid,
                            backend_metrics: backend_metrics
                                .into_iter()
                                .map(|m| BackendMetrics {
                                    backend_id: m.backend_id,
                                    packets_in: m.packets_in,
                                    packets_out: m.packets_out,
                                    bytes_in: m.bytes_in,
                                    bytes_out: m.bytes_out,
                                    packets_dropped: m.packets_dropped,
                                    packets_challenged: m.packets_challenged,
                                    drops_by_reason: m.drops_by_reason,
                                })
                                .collect(),
                        };

                        let mut client_guard = client.lock().await;
                        if let Some(ref mut grpc_client) = *client_guard {
                            match timeout(request_timeout, grpc_client.report_metrics(request)).await {
                                Ok(Ok(_)) => {
                                    debug!("Metrics reported successfully");
                                }
                                Ok(Err(e)) => {
                                    warn!("Failed to report metrics: {}", e);
                                }
                                Err(_) => {
                                    warn!("Metrics report timeout");
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    /// Spawn configuration streaming task
    fn spawn_config_stream_task(&self) -> tokio::task::JoinHandle<()> {
        let client = Arc::clone(&self.client);
        let worker_id = Arc::clone(&self.worker_id);
        let state = Arc::clone(&self.state);
        let config_version = Arc::clone(&self.config_version);
        let config_sync = Arc::clone(&self.config_sync);
        let _request_timeout = self.config.request_timeout;
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("Config stream task shutting down");
                        break;
                    }
                    _ = async {
                        // Wait until connected
                        loop {
                            let current_state = *state.read();
                            if current_state == ConnectionState::Connected {
                                break;
                            }
                            sleep(Duration::from_secs(1)).await;
                        }

                        let wid = {
                            let guard = worker_id.read();
                            guard.clone()
                        };
                        let wid = match wid {
                            Some(id) => id,
                            None => {
                                sleep(Duration::from_secs(1)).await;
                                return;
                            }
                        };

                        // Start config stream
                        let mut client_guard = client.lock().await;
                        if let Some(ref mut grpc_client) = *client_guard {
                            let request = StreamConfigRequest { worker_id: wid };

                            match grpc_client.stream_config(request).await {
                                Ok(response) => {
                                    let mut stream = response.into_inner();
                                    drop(client_guard); // Release lock while streaming

                                    info!("Configuration stream established");

                                    while let Ok(Some(config)) = stream.message().await {
                                        info!(
                                            "Received configuration update version {}",
                                            config.version
                                        );

                                        // Apply configuration
                                        if let Err(e) = config_sync.apply_config(&config).await {
                                            error!("Failed to apply configuration: {}", e);
                                        } else {
                                            config_version.store(config.version, Ordering::SeqCst);
                                        }
                                    }

                                    warn!("Configuration stream ended, will reconnect");
                                }
                                Err(e) => {
                                    error!("Failed to start config stream: {}", e);
                                }
                            }
                        } else {
                            drop(client_guard);
                        }

                        // Wait before retry
                        sleep(Duration::from_secs(5)).await;
                    } => {}
                }
            }
        })
    }

    /// Spawn reconnection monitoring task
    fn spawn_reconnection_task(&self) -> tokio::task::JoinHandle<()> {
        let client = Arc::clone(&self.client);
        let state = Arc::clone(&self.state);
        let worker_id = Arc::clone(&self.worker_id);
        let reconnect_attempts = Arc::clone(&self.reconnect_attempts);
        let last_heartbeat = Arc::clone(&self.last_heartbeat);
        let config = self.config.clone();
        let _interfaces = Arc::clone(&self.interfaces);
        let state_tx = self.state_tx.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        let this_config = self.config.clone();
        let this_interfaces = Arc::clone(&self.interfaces);
        let this_config_version = Arc::clone(&self.config_version);
        let this_config_sync = Arc::clone(&self.config_sync);

        tokio::spawn(async move {
            let mut check_interval = interval(Duration::from_secs(5));

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("Reconnection task shutting down");
                        break;
                    }
                    _ = check_interval.tick() => {
                        let current_state = *state.read();

                        // Check if we need to reconnect
                        let needs_reconnect = match current_state {
                            ConnectionState::Connected => {
                                // Check if heartbeat has been too long
                                let last = last_heartbeat.load(Ordering::SeqCst);
                                if last == 0 {
                                    false
                                } else {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    let elapsed = now.saturating_sub(last);
                                    // Consider disconnected if no heartbeat for 3x interval
                                    elapsed > config.heartbeat_interval.as_secs() * 3
                                }
                            }
                            ConnectionState::Disconnected | ConnectionState::Reconnecting => true,
                            _ => false,
                        };

                        if !needs_reconnect {
                            continue;
                        }

                        *state.write() = ConnectionState::Reconnecting;
                        let _ = state_tx.send(ConnectionState::Reconnecting);

                        // Calculate backoff delay
                        let attempt = reconnect_attempts.fetch_add(1, Ordering::SeqCst);
                        let delay = calculate_backoff_delay(
                            attempt,
                            config.reconnect_delay,
                            config.max_reconnect_delay,
                        );

                        info!(
                            "Attempting to reconnect (attempt {}), waiting {:?}",
                            attempt + 1,
                            delay
                        );

                        sleep(delay).await;

                        // Check max attempts
                        if config.max_reconnect_attempts > 0
                            && attempt >= config.max_reconnect_attempts
                        {
                            error!(
                                "Max reconnection attempts ({}) reached, giving up",
                                config.max_reconnect_attempts
                            );
                            *state.write() = ConnectionState::Disconnected;
                            let _ = state_tx.send(ConnectionState::Disconnected);
                            continue;
                        }

                        // Attempt reconnection
                        match reconnect(
                            &this_config,
                            &this_interfaces,
                            &client,
                            &worker_id,
                            &this_config_version,
                            &this_config_sync,
                        )
                        .await
                        {
                            Ok(_) => {
                                info!("Successfully reconnected to control plane");
                                *state.write() = ConnectionState::Connected;
                                let _ = state_tx.send(ConnectionState::Connected);
                                reconnect_attempts.store(0, Ordering::SeqCst);

                                // Update last heartbeat
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                last_heartbeat.store(now, Ordering::SeqCst);
                            }
                            Err(e) => {
                                warn!("Reconnection attempt failed: {}", e);
                            }
                        }
                    }
                }
            }
        })
    }

    /// Apply configuration from control plane
    async fn apply_configuration(&self, config: &FilterConfig) -> Result<()> {
        self.config_sync.apply_config(config).await?;
        self.config_version.store(config.version, Ordering::SeqCst);
        Ok(())
    }

    /// Update last heartbeat timestamp
    fn update_last_heartbeat(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_heartbeat.store(now, Ordering::SeqCst);
    }

    /// Report an attack to the control plane
    pub async fn report_attack(&self, attack: AttackInfo) -> Result<()> {
        let worker_id = self
            .worker_id
            .read()
            .clone()
            .ok_or_else(|| Error::Internal("Not registered".to_string()))?;

        let request = ReportAttackRequest {
            worker_id,
            backend_id: attack.backend_id,
            attack_type: attack.attack_type,
            attack_pps: attack.attack_pps,
            attack_bps: attack.attack_bps,
            sources: attack
                .sources
                .into_iter()
                .map(|s| pistonprotection_proto::worker::AttackSourceInfo {
                    ip: Some(s.ip.into()),
                    packets: s.packets,
                    bytes: s.bytes,
                })
                .collect(),
        };

        let mut client_guard = self.client.lock().await;
        if let Some(ref mut grpc_client) = *client_guard {
            let response = timeout(
                self.config.request_timeout,
                grpc_client.report_attack(request),
            )
            .await
            .map_err(|_| Error::Internal("Attack report timeout".to_string()))?
            .map_err(|e| Error::Internal(format!("Failed to report attack: {}", e)))?;

            let response = response.into_inner();

            // Apply any immediate mitigation actions
            if !response.block_updates.is_empty() {
                info!(
                    "Received {} block updates from control plane",
                    response.block_updates.len()
                );
                self.config_sync
                    .apply_map_updates(&response.block_updates)
                    .await?;
            }

            if response.escalate_protection {
                info!(
                    "Protection escalated to level {}",
                    response.new_protection_level
                );
                // The config sync manager will handle this
            }
        }

        Ok(())
    }

    /// Fetch configuration on-demand
    pub async fn fetch_config(&self) -> Result<FilterConfig> {
        let worker_id = self
            .worker_id
            .read()
            .clone()
            .ok_or_else(|| Error::Internal("Not registered".to_string()))?;

        let current_version = self.config_version.load(Ordering::SeqCst);

        let request = GetConfigRequest {
            worker_id,
            current_version,
        };

        let mut client_guard = self.client.lock().await;
        if let Some(ref mut grpc_client) = *client_guard {
            let response = timeout(self.config.request_timeout, grpc_client.get_config(request))
                .await
                .map_err(|_| Error::Internal("Get config timeout".to_string()))?
                .map_err(|e| Error::Internal(format!("Failed to get config: {}", e)))?;

            let response = response.into_inner();

            if response.up_to_date {
                // Return current config from sync manager
                return self
                    .config_sync
                    .current_config()
                    .ok_or_else(|| Error::Internal("No configuration loaded".to_string()));
            }

            if let Some(config) = response.config {
                // Apply and return
                self.apply_configuration(&config).await?;
                return Ok(config);
            }
        }

        Err(Error::Internal("No client connection".to_string()))
    }

    /// Gracefully shutdown the control plane client
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down control plane client");

        self.set_state(ConnectionState::ShuttingDown);
        self.running.store(false, Ordering::SeqCst);

        // Send shutdown signal
        let _ = self.shutdown_tx.send(());

        // Deregister from control plane
        if let Some(worker_id) = self.worker_id.read().clone() {
            let mut client_guard = self.client.lock().await;
            if let Some(ref mut grpc_client) = *client_guard {
                let request = DeregisterRequest { worker_id };
                let _ = timeout(Duration::from_secs(5), grpc_client.deregister(request)).await;
            }
        }

        self.set_state(ConnectionState::Disconnected);

        Ok(())
    }
}

/// Reconnect to control plane
async fn reconnect(
    config: &ControlPlaneConfig,
    interfaces: &[NetworkInterface],
    client: &Arc<Mutex<Option<WorkerServiceClient<Channel>>>>,
    worker_id: &Arc<RwLock<Option<String>>>,
    config_version: &Arc<AtomicU32>,
    config_sync: &Arc<ConfigSyncManager>,
) -> Result<()> {
    // Create new channel
    let endpoint = Endpoint::from_shared(config.address.clone())
        .map_err(|e| Error::Internal(format!("Invalid control plane address: {}", e)))?
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout);

    let channel = timeout(config.connect_timeout, endpoint.connect())
        .await
        .map_err(|_| Error::Internal("Connection timeout".to_string()))?
        .map_err(|e| Error::Internal(format!("Failed to connect: {}", e)))?;

    let mut new_client = WorkerServiceClient::new(channel);

    // Re-register (in case we were removed from control plane)
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    let kernel_version = sysinfo::System::kernel_version().unwrap_or_default();
    let (kernel_major, kernel_minor) = parse_kernel_version(&kernel_version);

    let worker_info = Worker {
        id: worker_id.read().clone().unwrap_or_default(),
        node_name: config.node_name.clone(),
        hostname: hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
        interfaces: interfaces
            .iter()
            .map(|iface| pistonprotection_proto::worker::NetworkInterface {
                name: iface.name.clone(),
                ip_address: iface.ip_address.map(|ip| ip.into()),
                mac_address: iface
                    .mac_address
                    .map(|mac| {
                        mac.iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(":")
                    })
                    .unwrap_or_default(),
                xdp_status: None,
                rx_bytes: 0,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
                rx_dropped: 0,
                tx_dropped: 0,
            })
            .collect(),
        capabilities: Some(WorkerCapabilities {
            xdp_native: check_xdp_support(XdpSupportLevel::Native),
            xdp_driver: check_xdp_support(XdpSupportLevel::Driver),
            xdp_offload: check_xdp_support(XdpSupportLevel::Offload),
            bpf_helpers: get_available_bpf_helpers(),
            max_bpf_stack_size: 512,
            max_map_entries: 1_000_000,
            cpu_cores: sys.cpus().len() as u32,
            memory_bytes: sys.total_memory(),
            network_drivers: get_network_drivers(interfaces),
            kernel_version,
            kernel_major,
            kernel_minor,
        }),
        status: WorkerStatus::Registering.into(),
        labels: config.labels.clone(),
        registered_at: None,
        last_heartbeat: None,
    };

    let register_request = RegisterRequest {
        worker: Some(worker_info),
    };

    let response = timeout(
        config.request_timeout,
        new_client.register(register_request),
    )
    .await
    .map_err(|_| Error::Internal("Registration timeout".to_string()))?
    .map_err(|e| Error::Internal(format!("Registration failed: {}", e)))?;

    let response = response.into_inner();

    // Update worker ID (might be different on re-registration)
    *worker_id.write() = Some(response.worker_id.clone());

    // Apply configuration if provided
    if let Some(initial_config) = response.initial_config {
        config_sync.apply_config(&initial_config).await?;
        config_version.store(initial_config.version, Ordering::SeqCst);
    }

    // Store new client
    *client.lock().await = Some(new_client);

    Ok(())
}

/// Calculate exponential backoff delay
fn calculate_backoff_delay(attempt: u32, base_delay: Duration, max_delay: Duration) -> Duration {
    let multiplier = 2u64.saturating_pow(attempt.min(10));
    let delay = base_delay.as_millis() as u64 * multiplier;
    let delay_ms = delay.min(max_delay.as_millis() as u64);

    // Add jitter (10% of delay)
    let jitter = (delay_ms / 10).max(100);
    let jitter_offset = (rand_u64() % (jitter * 2)) as i64 - jitter as i64;
    let final_delay = (delay_ms as i64 + jitter_offset).max(0) as u64;

    Duration::from_millis(final_delay)
}

/// Simple random number generator (for jitter)
fn rand_u64() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1)
}

/// Parse kernel version string (e.g., "5.15.0" -> (5, 15))
fn parse_kernel_version(version: &str) -> (u32, u32) {
    let parts: Vec<&str> = version.split('.').collect();
    let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor)
}

/// XDP support level
enum XdpSupportLevel {
    Native,
    Driver,
    Offload,
}

/// Check XDP support level
fn check_xdp_support(_level: XdpSupportLevel) -> bool {
    // In a real implementation, this would check kernel capabilities
    // For now, assume basic support is available
    true
}

/// Get available BPF helpers
fn get_available_bpf_helpers() -> Vec<String> {
    // In a real implementation, this would probe the kernel
    vec![
        "bpf_map_lookup_elem".to_string(),
        "bpf_map_update_elem".to_string(),
        "bpf_map_delete_elem".to_string(),
        "bpf_ktime_get_ns".to_string(),
        "bpf_get_prandom_u32".to_string(),
        "bpf_xdp_adjust_head".to_string(),
        "bpf_xdp_adjust_tail".to_string(),
        "bpf_fib_lookup".to_string(),
    ]
}

/// Get network drivers for interfaces
fn get_network_drivers(interfaces: &[NetworkInterface]) -> Vec<String> {
    // In a real implementation, this would read from /sys/class/net/<iface>/device/driver
    interfaces
        .iter()
        .filter(|i| i.supports_xdp())
        .map(|i| format!("driver_{}", i.name))
        .collect()
}

/// Collect worker-level metrics
fn collect_worker_metrics(
    _loader: &Arc<RwLock<EbpfLoader>>,
    interfaces: &Arc<Vec<NetworkInterface>>,
) -> WorkerMetricsSnapshot {
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();

    let cpu_percent = sys.global_cpu_usage();
    let memory_percent = (sys.used_memory() as f32 / sys.total_memory() as f32) * 100.0;

    // Collect interface metrics
    let interface_metrics: Vec<InterfaceMetricsSnapshot> = interfaces
        .iter()
        .map(|iface| {
            // In a real implementation, read from /sys/class/net/<iface>/statistics/*
            InterfaceMetricsSnapshot {
                name: iface.name.clone(),
                rx_pps: 0,
                tx_pps: 0,
                rx_bps: 0,
                tx_bps: 0,
                xdp_pass: 0,
                xdp_drop: 0,
                xdp_redirect: 0,
            }
        })
        .collect();

    WorkerMetricsSnapshot {
        cpu_percent,
        memory_percent,
        interfaces: interface_metrics,
    }
}

/// Collect backend-specific metrics
fn collect_backend_metrics(loader: &Arc<RwLock<EbpfLoader>>) -> Vec<BackendMetricsSnapshot> {
    let loader_guard = loader.read();
    let maps = loader_guard.maps();
    let _map_manager = maps.read();

    // In a real implementation, read from eBPF maps
    // For now, return empty
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kernel_version() {
        assert_eq!(parse_kernel_version("5.15.0-generic"), (5, 15));
        assert_eq!(parse_kernel_version("6.1.21"), (6, 1));
        assert_eq!(parse_kernel_version("4.19"), (4, 19));
        assert_eq!(parse_kernel_version("invalid"), (0, 0));
    }

    #[test]
    fn test_calculate_backoff_delay() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);

        let d0 = calculate_backoff_delay(0, base, max);
        assert!(d0 >= Duration::from_millis(900) && d0 <= Duration::from_millis(1100));

        let d3 = calculate_backoff_delay(3, base, max);
        // 2^3 = 8 seconds base
        assert!(d3 >= Duration::from_secs(7) && d3 <= Duration::from_secs(9));
    }

    #[test]
    fn test_control_plane_config_default() {
        let config = ControlPlaneConfig::default();
        assert_eq!(config.address, "http://gateway:50051");
        assert_eq!(config.heartbeat_interval, Duration::from_secs(10));
    }

    #[test]
    fn test_connection_state_display() {
        assert_eq!(format!("{}", ConnectionState::Connected), "connected");
        assert_eq!(format!("{}", ConnectionState::Disconnected), "disconnected");
        assert_eq!(format!("{}", ConnectionState::Reconnecting), "reconnecting");
    }
}
