//! DDoSProtection Controller
//!
//! This controller manages DDoSProtection custom resources, handling:
//! - Worker Deployment creation and updates
//! - Service creation for workers
//! - ConfigMap management for backend configuration
//! - Gateway synchronization
//! - Status updates

use crate::client::GatewayClient;
use crate::crd::{
    Condition, DDoSProtection, DDoSProtectionStatus, Phase, COMPONENT_LABEL, FINALIZER,
    INSTANCE_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, NAME_LABEL, WORKER_IMAGE,
};
use crate::error::{Error, Result};
use crate::metrics::{Metrics, ReconciliationTimer};

use k8s_openapi::api::{
    apps::v1::{Deployment, DeploymentSpec, DeploymentStatus as K8sDeploymentStatus},
    core::v1::{
        ConfigMap, Container, ContainerPort, EnvVar, HTTPGetAction, PodSpec, PodTemplateSpec,
        Probe, ResourceRequirements, Service, ServicePort, ServiceSpec, Volume, VolumeMount,
    },
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference};
use k8s_openapi::api::core::v1::ObjectReference;
use kube::{
    api::{Api, ObjectMeta, Patch, PatchParams, PostParams},
    runtime::{
        controller::Action,
        events::{Event, EventType, Recorder, Reporter},
        finalizer::{finalizer, Event as FinalizerEvent},
    },
    Client, Resource, ResourceExt,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Context shared across reconciliation calls
pub struct Context {
    /// Kubernetes client
    pub client: Client,
    /// Gateway gRPC client
    pub gateway_client: GatewayClient,
    /// Metrics collector
    pub metrics: Arc<Metrics>,
    /// Event reporter
    pub reporter: Reporter,
}

impl Context {
    /// Create a new context
    pub fn new(
        client: Client,
        gateway_client: GatewayClient,
        metrics: Arc<Metrics>,
        reporter: Reporter,
    ) -> Self {
        Self {
            client,
            gateway_client,
            metrics,
            reporter,
        }
    }

    /// Create a recorder for a specific object
    fn recorder(&self, obj_ref: ObjectReference) -> Recorder {
        Recorder::new(self.client.clone(), self.reporter.clone(), obj_ref)
    }
}

/// Reconcile a DDoSProtection resource
///
/// This is the main reconciliation loop that handles all changes to DDoSProtection resources.
pub async fn reconcile(
    ddos: Arc<DDoSProtection>,
    ctx: Arc<Context>,
) -> std::result::Result<Action, Error> {
    let name = ddos.name_any();
    let namespace = ddos.namespace().unwrap_or_else(|| "default".to_string());

    info!(
        "Reconciling DDoSProtection {}/{} (generation: {:?})",
        namespace,
        name,
        ddos.metadata.generation
    );

    let timer = ReconciliationTimer::new(&ctx.metrics, "DDoSProtection", &namespace);

    // Create object reference for events
    let obj_ref = ObjectReference {
        api_version: Some(DDoSProtection::api_version(&()).to_string()),
        kind: Some(DDoSProtection::kind(&()).to_string()),
        name: Some(name.clone()),
        namespace: Some(namespace.clone()),
        uid: ddos.metadata.uid.clone(),
        ..Default::default()
    };
    let recorder = ctx.recorder(obj_ref);

    // Get API for this namespace
    let ddos_api: Api<DDoSProtection> = Api::namespaced(ctx.client.clone(), &namespace);

    // Handle finalizer
    let result = finalizer(&ddos_api, FINALIZER, ddos, |event| async {
        match event {
            FinalizerEvent::Apply(ddos) => {
                reconcile_apply(&ddos, &ctx, &recorder, &namespace, &name).await
            }
            FinalizerEvent::Cleanup(ddos) => {
                reconcile_cleanup(&ddos, &ctx, &recorder, &namespace, &name).await
            }
        }
    })
    .await;

    match result {
        Ok(action) => {
            timer.success();
            Ok(action)
        }
        Err(e) => {
            let error = match e {
                kube::runtime::finalizer::Error::ApplyFailed(e) => e,
                kube::runtime::finalizer::Error::CleanupFailed(e) => e,
                kube::runtime::finalizer::Error::AddFinalizer(e) => Error::KubeError(e),
                kube::runtime::finalizer::Error::RemoveFinalizer(e) => Error::KubeError(e),
                kube::runtime::finalizer::Error::UnnamedObject => {
                    Error::Permanent("Resource has no name".to_string())
                }
                kube::runtime::finalizer::Error::InvalidFinalizer => {
                    Error::Permanent("Invalid finalizer".to_string())
                }
            };
            timer.error(error.category());
            Err(error)
        }
    }
}

/// Apply reconciliation - handle create/update
async fn reconcile_apply(
    ddos: &DDoSProtection,
    ctx: &Context,
    recorder: &Recorder,
    namespace: &str,
    name: &str,
) -> Result<Action> {
    info!("Applying DDoSProtection {}/{}", namespace, name);

    // Validate the resource
    validate_ddos_protection(ddos)?;

    // Record event
    recorder
        .publish(Event {
            type_: EventType::Normal,
            reason: "Reconciling".to_string(),
            note: Some("Starting reconciliation".to_string()),
            action: "Reconcile".to_string(),
            secondary: None,
        })
        .await
        .ok();

    // 1. Create/update worker Deployment
    let deployment_status = reconcile_deployment(&ctx.client, ddos).await?;

    // 2. Create/update worker Service
    reconcile_service(&ctx.client, ddos).await?;

    // 3. Create/update ConfigMap
    reconcile_configmap(&ctx.client, ddos).await?;

    // 4. Sync to gateway
    let sync_start = std::time::Instant::now();
    let gateway_synced = match ctx.gateway_client.sync_ddos_protection(ddos).await {
        Ok(result) => {
            info!(
                "Successfully synced DDoSProtection {}/{} to gateway: {}",
                namespace, name, result.message
            );
            ctx.metrics.record_gateway_sync(
                "DDoSProtection",
                namespace,
                name,
                sync_start.elapsed().as_secs_f64(),
                true,
            );
            true
        }
        Err(e) => {
            warn!(
                "Failed to sync DDoSProtection {}/{} to gateway: {}",
                namespace, name, e
            );
            ctx.metrics.record_gateway_sync(
                "DDoSProtection",
                namespace,
                name,
                sync_start.elapsed().as_secs_f64(),
                false,
            );
            ctx.metrics
                .record_gateway_sync_error("DDoSProtection", e.category());

            // Continue with reconciliation, but mark as not synced
            false
        }
    };

    // 5. Update status
    let phase = determine_phase(&deployment_status, gateway_synced);
    let ready_workers = deployment_status
        .as_ref()
        .and_then(|s| s.ready_replicas)
        .unwrap_or(0);
    let available_workers = deployment_status
        .as_ref()
        .and_then(|s| s.available_replicas)
        .unwrap_or(0);

    let status = build_status(ddos, phase, ready_workers, gateway_synced, None);
    update_status(&ctx.client, namespace, name, status).await?;

    // Update metrics
    ctx.metrics.set_backend_counts(
        namespace,
        name,
        ddos.spec.backends.len() as i64,
        ddos.spec.backends.len() as i64, // Assume all healthy for now
    );
    ctx.metrics.set_worker_counts(
        namespace,
        name,
        ddos.spec.replicas as i64,
        ready_workers as i64,
        available_workers as i64,
    );

    // Record success event
    recorder
        .publish(Event {
            type_: EventType::Normal,
            reason: "Reconciled".to_string(),
            note: Some(format!(
                "Successfully reconciled with {} backends",
                ddos.spec.backends.len()
            )),
            action: "Reconcile".to_string(),
            secondary: None,
        })
        .await
        .ok();

    // Determine requeue interval based on status
    let requeue_after = if gateway_synced && phase == Phase::Active {
        Duration::from_secs(300) // 5 minutes when healthy
    } else {
        Duration::from_secs(30) // 30 seconds when not fully healthy
    };

    Ok(Action::requeue(requeue_after))
}

/// Cleanup reconciliation - handle delete
async fn reconcile_cleanup(
    _ddos: &DDoSProtection,
    ctx: &Context,
    recorder: &Recorder,
    namespace: &str,
    name: &str,
) -> Result<Action> {
    info!("Cleaning up DDoSProtection {}/{}", namespace, name);

    // Record event
    recorder
        .publish(Event {
            type_: EventType::Normal,
            reason: "Deleting".to_string(),
            note: Some("Cleaning up resources".to_string()),
            action: "Delete".to_string(),
            secondary: None,
        })
        .await
        .ok();

    // Remove from gateway
    if let Err(e) = ctx.gateway_client.delete_ddos_protection(namespace, name).await {
        warn!(
            "Failed to remove DDoSProtection {}/{} from gateway: {}",
            namespace, name, e
        );
        // Continue with cleanup even if gateway sync fails
    }

    // Kubernetes will garbage collect owned resources (Deployment, Service, ConfigMap)
    // due to owner references

    info!("Cleanup complete for DDoSProtection {}/{}", namespace, name);

    Ok(Action::await_change())
}

/// Validate DDoSProtection resource
fn validate_ddos_protection(ddos: &DDoSProtection) -> Result<()> {
    // Check protection level
    if ddos.spec.protection_level > 5 {
        return Err(Error::validation(
            "protectionLevel",
            "must be between 1 and 5",
        ));
    }

    // Check backends
    if ddos.spec.backends.is_empty() {
        return Err(Error::validation("backends", "at least one backend is required"));
    }

    for backend in &ddos.spec.backends {
        if backend.name.is_empty() {
            return Err(Error::validation("backends[].name", "backend name is required"));
        }
        if backend.address.is_empty() {
            return Err(Error::validation("backends[].address", "backend address is required"));
        }
    }

    // Check replicas
    if ddos.spec.replicas < 1 {
        return Err(Error::validation("replicas", "must be at least 1"));
    }

    Ok(())
}

/// Reconcile the worker Deployment
async fn reconcile_deployment(
    client: &Client,
    ddos: &DDoSProtection,
) -> Result<Option<K8sDeploymentStatus>> {
    let name = ddos.name_any();
    let namespace = ddos.namespace().unwrap_or_else(|| "default".to_string());
    let deployment_name = format!("{}-worker", name);

    debug!("Reconciling deployment {}/{}", namespace, deployment_name);

    let labels = create_labels(&name, "worker");
    let owner_ref = create_owner_reference(ddos);

    // Build container
    let container = Container {
        name: "worker".to_string(),
        image: Some(WORKER_IMAGE.to_string()),
        image_pull_policy: Some("IfNotPresent".to_string()),
        ports: Some(vec![
            ContainerPort {
                container_port: 8080,
                name: Some("http".to_string()),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            },
            ContainerPort {
                container_port: 9090,
                name: Some("metrics".to_string()),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            },
            ContainerPort {
                container_port: 50051,
                name: Some("grpc".to_string()),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            },
        ]),
        env: Some(vec![
            EnvVar {
                name: "RUST_LOG".to_string(),
                value: Some("info".to_string()),
                ..Default::default()
            },
            EnvVar {
                name: "PROTECTION_LEVEL".to_string(),
                value: Some(ddos.spec.protection_level.to_string()),
                ..Default::default()
            },
            EnvVar {
                name: "CONFIG_PATH".to_string(),
                value: Some("/etc/pistonprotection/backends.json".to_string()),
                ..Default::default()
            },
            EnvVar {
                name: "POD_NAME".to_string(),
                value_from: Some(k8s_openapi::api::core::v1::EnvVarSource {
                    field_ref: Some(k8s_openapi::api::core::v1::ObjectFieldSelector {
                        field_path: "metadata.name".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            EnvVar {
                name: "POD_NAMESPACE".to_string(),
                value_from: Some(k8s_openapi::api::core::v1::EnvVarSource {
                    field_ref: Some(k8s_openapi::api::core::v1::ObjectFieldSelector {
                        field_path: "metadata.namespace".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]),
        resources: Some(build_resources(&ddos.spec.resources)),
        volume_mounts: Some(vec![VolumeMount {
            name: "config".to_string(),
            mount_path: "/etc/pistonprotection".to_string(),
            read_only: Some(true),
            ..Default::default()
        }]),
        liveness_probe: Some(Probe {
            http_get: Some(HTTPGetAction {
                path: Some("/healthz".to_string()),
                port: k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(8080),
                ..Default::default()
            }),
            initial_delay_seconds: Some(10),
            period_seconds: Some(10),
            timeout_seconds: Some(5),
            failure_threshold: Some(3),
            ..Default::default()
        }),
        readiness_probe: Some(Probe {
            http_get: Some(HTTPGetAction {
                path: Some("/readyz".to_string()),
                port: k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(8080),
                ..Default::default()
            }),
            initial_delay_seconds: Some(5),
            period_seconds: Some(5),
            timeout_seconds: Some(3),
            failure_threshold: Some(3),
            ..Default::default()
        }),
        security_context: Some(k8s_openapi::api::core::v1::SecurityContext {
            privileged: Some(true), // Required for eBPF/XDP
            capabilities: Some(k8s_openapi::api::core::v1::Capabilities {
                add: Some(vec![
                    "NET_ADMIN".to_string(),
                    "SYS_ADMIN".to_string(),
                    "BPF".to_string(),
                    "NET_RAW".to_string(),
                ]),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    // Build deployment
    let deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(deployment_name.clone()),
            namespace: Some(namespace.clone()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(ddos.spec.replicas),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels.clone()),
                    annotations: ddos.spec.annotations.clone(),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![container],
                    volumes: Some(vec![Volume {
                        name: "config".to_string(),
                        config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                            name: Some(format!("{}-config", name)),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
                    node_selector: ddos.spec.node_selector.clone(),
                    host_network: Some(true), // Required for XDP
                    dns_policy: Some("ClusterFirstWithHostNet".to_string()),
                    service_account_name: Some("pistonprotection-worker".to_string()),
                    termination_grace_period_seconds: Some(30),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    // Apply deployment
    let api: Api<Deployment> = Api::namespaced(client.clone(), &namespace);
    let result = api
        .patch(
            &deployment_name,
            &PatchParams::apply("pistonprotection-operator").force(),
            &Patch::Apply(&deployment),
        )
        .await
        .map_err(Error::KubeError)?;

    debug!("Deployment {}/{} reconciled", namespace, deployment_name);

    Ok(result.status)
}

/// Reconcile the worker Service
async fn reconcile_service(client: &Client, ddos: &DDoSProtection) -> Result<()> {
    let name = ddos.name_any();
    let namespace = ddos.namespace().unwrap_or_else(|| "default".to_string());
    let service_name = format!("{}-worker", name);

    debug!("Reconciling service {}/{}", namespace, service_name);

    let labels = create_labels(&name, "worker");
    let selector_labels = create_selector_labels(&name);
    let owner_ref = create_owner_reference(ddos);

    let service = Service {
        metadata: ObjectMeta {
            name: Some(service_name.clone()),
            namespace: Some(namespace.clone()),
            labels: Some(labels),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(selector_labels),
            ports: Some(vec![
                ServicePort {
                    name: Some("http".to_string()),
                    port: 8080,
                    target_port: Some(
                        k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(8080),
                    ),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("metrics".to_string()),
                    port: 9090,
                    target_port: Some(
                        k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(9090),
                    ),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("grpc".to_string()),
                    port: 50051,
                    target_port: Some(
                        k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(50051),
                    ),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
            ]),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let api: Api<Service> = Api::namespaced(client.clone(), &namespace);
    api.patch(
        &service_name,
        &PatchParams::apply("pistonprotection-operator").force(),
        &Patch::Apply(&service),
    )
    .await
    .map_err(Error::KubeError)?;

    debug!("Service {}/{} reconciled", namespace, service_name);

    Ok(())
}

/// Reconcile the ConfigMap
async fn reconcile_configmap(client: &Client, ddos: &DDoSProtection) -> Result<()> {
    let name = ddos.name_any();
    let namespace = ddos.namespace().unwrap_or_else(|| "default".to_string());
    let configmap_name = format!("{}-config", name);

    debug!("Reconciling configmap {}/{}", namespace, configmap_name);

    let labels = create_labels(&name, "config");
    let owner_ref = create_owner_reference(ddos);

    // Serialize backend configuration
    let backends_json =
        serde_json::to_string_pretty(&ddos.spec.backends).map_err(Error::JsonError)?;

    // Build full configuration
    let config = serde_json::json!({
        "protection_level": ddos.spec.protection_level,
        "backends": ddos.spec.backends,
        "rate_limit": ddos.spec.rate_limit,
        "protocol": ddos.spec.protocol,
        "geo_filter": ddos.spec.geo_filter,
        "challenge_enabled": ddos.spec.challenge_enabled,
        "auto_escalate": ddos.spec.auto_escalate,
    });
    let config_json = serde_json::to_string_pretty(&config).map_err(Error::JsonError)?;

    let mut data = BTreeMap::new();
    data.insert("backends.json".to_string(), backends_json);
    data.insert("config.json".to_string(), config_json);
    data.insert(
        "protection_level".to_string(),
        ddos.spec.protection_level.to_string(),
    );

    let configmap = ConfigMap {
        metadata: ObjectMeta {
            name: Some(configmap_name.clone()),
            namespace: Some(namespace.clone()),
            labels: Some(labels),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    let api: Api<ConfigMap> = Api::namespaced(client.clone(), &namespace);
    api.patch(
        &configmap_name,
        &PatchParams::apply("pistonprotection-operator").force(),
        &Patch::Apply(&configmap),
    )
    .await
    .map_err(Error::KubeError)?;

    debug!("ConfigMap {}/{} reconciled", namespace, configmap_name);

    Ok(())
}

/// Update the status of a DDoSProtection resource
async fn update_status(
    client: &Client,
    namespace: &str,
    name: &str,
    status: DDoSProtectionStatus,
) -> Result<()> {
    let api: Api<DDoSProtection> = Api::namespaced(client.clone(), namespace);

    let patch = serde_json::json!({
        "status": status
    });

    api.patch_status(
        name,
        &PatchParams::apply("pistonprotection-operator"),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(Error::KubeError)?;

    debug!("Status updated for DDoSProtection {}/{}", namespace, name);

    Ok(())
}

/// Build status object
fn build_status(
    ddos: &DDoSProtection,
    phase: Phase,
    ready_workers: i32,
    gateway_synced: bool,
    error_message: Option<String>,
) -> DDoSProtectionStatus {
    let now = chrono::Utc::now().to_rfc3339();

    let mut conditions = Vec::new();

    // Ready condition
    conditions.push(Condition::new(
        "Ready",
        phase == Phase::Active,
        if phase == Phase::Active {
            "AllWorkersReady"
        } else {
            "WorkersNotReady"
        },
        if phase == Phase::Active {
            "All worker pods are ready"
        } else {
            "Some worker pods are not ready"
        },
    ));

    // GatewaySynced condition
    conditions.push(Condition::new(
        "GatewaySynced",
        gateway_synced,
        if gateway_synced {
            "SyncSucceeded"
        } else {
            "SyncFailed"
        },
        if gateway_synced {
            "Configuration synced to gateway"
        } else {
            "Failed to sync configuration to gateway"
        },
    ));

    // Progressing condition
    let progressing = phase == Phase::Provisioning || phase == Phase::Pending;
    conditions.push(Condition::new(
        "Progressing",
        progressing,
        if progressing {
            "Deploying"
        } else {
            "DeploymentComplete"
        },
        if progressing {
            "Deployment is in progress"
        } else {
            "Deployment is complete"
        },
    ));

    DDoSProtectionStatus {
        phase,
        backend_count: ddos.spec.backends.len() as i32,
        healthy_backends: ddos.spec.backends.len() as i32, // Assume all healthy
        ready_workers,
        desired_workers: ddos.spec.replicas,
        last_updated: Some(now),
        observed_generation: ddos.metadata.generation,
        conditions,
        metrics: None,
        gateway_synced,
        last_error: error_message,
        current_protection_level: Some(ddos.spec.protection_level),
    }
}

/// Determine the phase based on deployment status
fn determine_phase(
    deployment_status: &Option<K8sDeploymentStatus>,
    gateway_synced: bool,
) -> Phase {
    match deployment_status {
        Some(status) => {
            let ready = status.ready_replicas.unwrap_or(0);
            let desired = status.replicas.unwrap_or(0);
            let available = status.available_replicas.unwrap_or(0);

            if ready == 0 {
                Phase::Provisioning
            } else if ready < desired {
                Phase::Degraded
            } else if available < desired {
                Phase::Degraded
            } else if !gateway_synced {
                Phase::Degraded
            } else {
                Phase::Active
            }
        }
        None => Phase::Pending,
    }
}

/// Create standard labels
fn create_labels(instance: &str, component: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(NAME_LABEL.to_string(), "pistonprotection".to_string());
    labels.insert(INSTANCE_LABEL.to_string(), instance.to_string());
    labels.insert(COMPONENT_LABEL.to_string(), component.to_string());
    labels.insert(MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string());
    labels
}

/// Create selector labels (subset of full labels)
fn create_selector_labels(instance: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(NAME_LABEL.to_string(), "pistonprotection".to_string());
    labels.insert(INSTANCE_LABEL.to_string(), instance.to_string());
    labels.insert(COMPONENT_LABEL.to_string(), "worker".to_string());
    labels
}

/// Create owner reference
fn create_owner_reference(ddos: &DDoSProtection) -> OwnerReference {
    OwnerReference {
        api_version: DDoSProtection::api_version(&()).to_string(),
        kind: DDoSProtection::kind(&()).to_string(),
        name: ddos.name_any(),
        uid: ddos.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Build resource requirements
fn build_resources(
    resources: &Option<crate::crd::ResourceSpec>,
) -> ResourceRequirements {
    let (cpu_request, mem_request, cpu_limit, mem_limit) = match resources {
        Some(r) => (
            r.cpu_request.clone().unwrap_or_else(|| "100m".to_string()),
            r.memory_request
                .clone()
                .unwrap_or_else(|| "128Mi".to_string()),
            r.cpu_limit.clone().unwrap_or_else(|| "1000m".to_string()),
            r.memory_limit
                .clone()
                .unwrap_or_else(|| "512Mi".to_string()),
        ),
        None => (
            "100m".to_string(),
            "128Mi".to_string(),
            "1000m".to_string(),
            "512Mi".to_string(),
        ),
    };

    ResourceRequirements {
        requests: Some(BTreeMap::from([
            (
                "cpu".to_string(),
                k8s_openapi::apimachinery::pkg::api::resource::Quantity(cpu_request),
            ),
            (
                "memory".to_string(),
                k8s_openapi::apimachinery::pkg::api::resource::Quantity(mem_request),
            ),
        ])),
        limits: Some(BTreeMap::from([
            (
                "cpu".to_string(),
                k8s_openapi::apimachinery::pkg::api::resource::Quantity(cpu_limit),
            ),
            (
                "memory".to_string(),
                k8s_openapi::apimachinery::pkg::api::resource::Quantity(mem_limit),
            ),
        ])),
        ..Default::default()
    }
}

/// Error policy for the controller
pub fn error_policy(
    ddos: Arc<DDoSProtection>,
    error: &Error,
    _ctx: Arc<Context>,
) -> Action {
    let name = ddos.name_any();
    let namespace = ddos.namespace().unwrap_or_default();

    warn!(
        "Reconciliation error for DDoSProtection {}/{}: {:?}",
        namespace, name, error
    );

    // Determine requeue delay based on error type
    let delay = error.retry_delay();

    if error.is_permanent() {
        warn!(
            "Permanent error for DDoSProtection {}/{}, not requeuing",
            namespace, name
        );
        Action::await_change()
    } else {
        info!(
            "Requeuing DDoSProtection {}/{} in {:?}",
            namespace, name, delay
        );
        Action::requeue(delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{BackendSpec, Protocol};

    fn create_test_ddos() -> DDoSProtection {
        DDoSProtection {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                namespace: Some("default".to_string()),
                generation: Some(1),
                uid: Some("test-uid".to_string()),
                ..Default::default()
            },
            spec: crate::crd::DDoSProtectionSpec {
                backends: vec![BackendSpec {
                    name: "backend1".to_string(),
                    address: "10.0.0.1:25565".to_string(),
                    protocol: Protocol::MinecraftJava,
                    weight: 1,
                    health_check: None,
                    rate_limit: None,
                    proxy_protocol: None,
                    metadata: None,
                }],
                protection_level: 3,
                rate_limit: None,
                protocol: None,
                geo_filter: None,
                node_selector: None,
                replicas: 2,
                challenge_enabled: false,
                auto_escalate: true,
                annotations: None,
                resources: None,
            },
            status: None,
        }
    }

    #[test]
    fn test_validate_ddos_protection() {
        let ddos = create_test_ddos();
        assert!(validate_ddos_protection(&ddos).is_ok());
    }

    #[test]
    fn test_validate_invalid_protection_level() {
        let mut ddos = create_test_ddos();
        ddos.spec.protection_level = 10;
        assert!(validate_ddos_protection(&ddos).is_err());
    }

    #[test]
    fn test_validate_empty_backends() {
        let mut ddos = create_test_ddos();
        ddos.spec.backends = vec![];
        assert!(validate_ddos_protection(&ddos).is_err());
    }

    #[test]
    fn test_create_labels() {
        let labels = create_labels("my-protection", "worker");
        assert_eq!(
            labels.get(NAME_LABEL),
            Some(&"pistonprotection".to_string())
        );
        assert_eq!(
            labels.get(INSTANCE_LABEL),
            Some(&"my-protection".to_string())
        );
    }

    #[test]
    fn test_determine_phase() {
        // No status
        assert_eq!(determine_phase(&None, true), Phase::Pending);

        // All ready
        let status = K8sDeploymentStatus {
            replicas: Some(2),
            ready_replicas: Some(2),
            available_replicas: Some(2),
            ..Default::default()
        };
        assert_eq!(determine_phase(&Some(status), true), Phase::Active);

        // Partially ready
        let status = K8sDeploymentStatus {
            replicas: Some(2),
            ready_replicas: Some(1),
            available_replicas: Some(1),
            ..Default::default()
        };
        assert_eq!(determine_phase(&Some(status), true), Phase::Degraded);

        // Gateway not synced
        let status = K8sDeploymentStatus {
            replicas: Some(2),
            ready_replicas: Some(2),
            available_replicas: Some(2),
            ..Default::default()
        };
        assert_eq!(determine_phase(&Some(status), false), Phase::Degraded);
    }
}
