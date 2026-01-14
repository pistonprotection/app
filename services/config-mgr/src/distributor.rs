//! Configuration distribution to workers

use crate::config_store::ConfigStore;
use deadpool_redis::Pool as RedisPool;
use parking_lot::RwLock;
use pistonprotection_common::{error::Result, redis::CacheService};
use pistonprotection_proto::worker::FilterConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time::{Duration, interval};
use tracing::{debug, info, warn};

/// Worker registration info
#[derive(Debug, Clone)]
pub struct RegisteredWorker {
    pub worker_id: String,
    pub node_name: String,
    pub interfaces: Vec<String>,
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
    pub config_version: u32,
}

/// Configuration update notification
#[derive(Debug, Clone)]
pub struct ConfigUpdate {
    pub version: u32,
    pub backend_id: Option<String>,
}

/// Configuration distributor
pub struct ConfigDistributor {
    store: Arc<ConfigStore>,
    cache: Option<CacheService>,
    workers: RwLock<HashMap<String, RegisteredWorker>>,
    /// Broadcast channel for config updates
    config_tx: broadcast::Sender<ConfigUpdate>,
}

impl ConfigDistributor {
    pub fn new(store: Arc<ConfigStore>, redis: Option<RedisPool>) -> Self {
        let cache = redis.map(|pool| CacheService::new(pool, "piston:workers"));
        let (config_tx, _) = broadcast::channel(16);

        Self {
            store,
            cache,
            workers: RwLock::new(HashMap::new()),
            config_tx,
        }
    }

    /// Subscribe to configuration updates
    pub fn subscribe(&self) -> broadcast::Receiver<ConfigUpdate> {
        self.config_tx.subscribe()
    }

    /// Notify all subscribers of a config update
    pub fn notify_update(&self, version: u32, backend_id: Option<String>) {
        let _ = self.config_tx.send(ConfigUpdate {
            version,
            backend_id,
        });
    }

    /// Register a worker
    pub fn register_worker(&self, worker_id: String, node_name: String, interfaces: Vec<String>) {
        info!(
            worker_id = %worker_id,
            node_name = %node_name,
            "Worker registered"
        );

        self.workers.write().insert(
            worker_id.clone(),
            RegisteredWorker {
                worker_id,
                node_name,
                interfaces,
                last_heartbeat: chrono::Utc::now(),
                config_version: 0,
            },
        );
    }

    /// Deregister a worker
    pub fn deregister_worker(&self, worker_id: &str) {
        if self.workers.write().remove(worker_id).is_some() {
            info!(worker_id = %worker_id, "Worker deregistered");
        }
    }

    /// Update worker heartbeat
    pub fn update_heartbeat(&self, worker_id: &str, config_version: u32) {
        if let Some(worker) = self.workers.write().get_mut(worker_id) {
            worker.last_heartbeat = chrono::Utc::now();
            worker.config_version = config_version;
            debug!(worker_id = %worker_id, "Heartbeat updated");
        }
    }

    /// Get list of all workers
    pub fn list_workers(&self) -> Vec<RegisteredWorker> {
        self.workers.read().values().cloned().collect()
    }

    /// Get workers that need configuration updates
    pub fn get_outdated_workers(&self) -> Vec<RegisteredWorker> {
        let current_version = self.store.current_version();

        self.workers
            .read()
            .values()
            .filter(|w| w.config_version < current_version)
            .cloned()
            .collect()
    }

    /// Clean up stale workers (no heartbeat for > 60 seconds)
    pub fn cleanup_stale_workers(&self) {
        let now = chrono::Utc::now();
        let stale_threshold = chrono::Duration::seconds(60);

        let stale_workers: Vec<String> = self
            .workers
            .read()
            .iter()
            .filter(|(_, w)| now - w.last_heartbeat > stale_threshold)
            .map(|(id, _)| id.clone())
            .collect();

        let mut workers = self.workers.write();
        for worker_id in stale_workers {
            if workers.remove(&worker_id).is_some() {
                warn!(worker_id = %worker_id, "Removed stale worker");
            }
        }
    }

    /// Get current configuration for a worker
    pub async fn get_config_for_worker(&self, _worker_id: &str) -> Result<FilterConfig> {
        // For now, all workers get the same configuration
        // In the future, this could be customized per-worker
        self.store.generate_config().await
    }

    /// Check if worker needs config update
    pub fn needs_update(&self, _worker_id: &str, worker_version: u32) -> bool {
        self.store.current_version() > worker_version
    }

    /// Run the distribution loop
    pub async fn run_distribution_loop(&self) -> Result<()> {
        let mut cleanup_interval = interval(Duration::from_secs(30));
        let mut notify_interval = interval(Duration::from_secs(5));

        loop {
            tokio::select! {
                _ = cleanup_interval.tick() => {
                    self.cleanup_stale_workers();
                }
                _ = notify_interval.tick() => {
                    // Check for outdated workers and notify them
                    let outdated = self.get_outdated_workers();
                    if !outdated.is_empty() {
                        debug!(count = outdated.len(), "Workers need config update");
                        // Workers will fetch new config on next heartbeat
                        // or we could push via pub/sub
                        if let Some(ref cache) = self.cache {
                            for worker in &outdated {
                                let _ = cache
                                    .publish(
                                        &format!("worker:{}", worker.worker_id),
                                        "config_update",
                                    )
                                    .await;
                            }
                        }
                    }
                }
            }
        }
    }
}
