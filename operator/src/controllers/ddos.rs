//! DDoSProtection controller implementation

use crate::{DDoSProtection, DDoSProtectionStatus, Error};
use k8s_openapi::api::{
    apps::v1::{Deployment, DeploymentSpec},
    core::v1::{
        ConfigMap, Container, ContainerPort, EnvVar, PodSpec, PodTemplateSpec,
        ResourceRequirements, Service, ServicePort, ServiceSpec,
    },
};
use kube::{
    api::{Api, ObjectMeta, Patch, PatchParams},
    Client, ResourceExt,
};
use std::collections::BTreeMap;
use tracing::info;

const WORKER_IMAGE: &str = "pistonprotection/worker:latest";
const FINALIZER: &str = "pistonprotection.io/finalizer";

/// Create or update the worker Deployment for a DDoSProtection resource
pub async fn reconcile_deployment(
    client: &Client,
    ddos: &DDoSProtection,
) -> Result<(), Error> {
    let name = ddos.name_any();
    let namespace = ddos.namespace().unwrap_or_default();
    let deployment_name = format!("{}-worker", name);

    info!("Reconciling deployment {}/{}", namespace, deployment_name);

    let labels = BTreeMap::from([
        ("app.kubernetes.io/name".to_string(), "pistonprotection-worker".to_string()),
        ("app.kubernetes.io/instance".to_string(), name.clone()),
        ("app.kubernetes.io/component".to_string(), "worker".to_string()),
        ("app.kubernetes.io/managed-by".to_string(), "pistonprotection-operator".to_string()),
    ]);

    let deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(deployment_name.clone()),
            namespace: Some(namespace.clone()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![ddos.controller_owner_ref(&()).unwrap()]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(ddos.spec.replicas),
            selector: k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels.clone()),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "worker".to_string(),
                        image: Some(WORKER_IMAGE.to_string()),
                        image_pull_policy: Some("Always".to_string()),
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
                        ]),
                        resources: Some(ResourceRequirements {
                            requests: Some(BTreeMap::from([
                                ("cpu".to_string(), k8s_openapi::apimachinery::pkg::api::resource::Quantity("100m".to_string())),
                                ("memory".to_string(), k8s_openapi::apimachinery::pkg::api::resource::Quantity("128Mi".to_string())),
                            ])),
                            limits: Some(BTreeMap::from([
                                ("cpu".to_string(), k8s_openapi::apimachinery::pkg::api::resource::Quantity("1000m".to_string())),
                                ("memory".to_string(), k8s_openapi::apimachinery::pkg::api::resource::Quantity("512Mi".to_string())),
                            ])),
                            ..Default::default()
                        }),
                        security_context: Some(k8s_openapi::api::core::v1::SecurityContext {
                            privileged: Some(true), // Required for eBPF
                            capabilities: Some(k8s_openapi::api::core::v1::Capabilities {
                                add: Some(vec![
                                    "NET_ADMIN".to_string(),
                                    "SYS_ADMIN".to_string(),
                                    "BPF".to_string(),
                                ]),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    node_selector: ddos.spec.node_selector.clone(),
                    host_network: Some(true), // Required for XDP
                    dns_policy: Some("ClusterFirstWithHostNet".to_string()),
                    service_account_name: Some("pistonprotection-worker".to_string()),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    let api: Api<Deployment> = Api::namespaced(client.clone(), &namespace);
    api.patch(
        &deployment_name,
        &PatchParams::apply("pistonprotection-operator"),
        &Patch::Apply(&deployment),
    )
    .await
    .map_err(Error::KubeError)?;

    Ok(())
}

/// Create or update the Service for a DDoSProtection resource
pub async fn reconcile_service(
    client: &Client,
    ddos: &DDoSProtection,
) -> Result<(), Error> {
    let name = ddos.name_any();
    let namespace = ddos.namespace().unwrap_or_default();
    let service_name = format!("{}-worker", name);

    info!("Reconciling service {}/{}", namespace, service_name);

    let labels = BTreeMap::from([
        ("app.kubernetes.io/name".to_string(), "pistonprotection-worker".to_string()),
        ("app.kubernetes.io/instance".to_string(), name.clone()),
    ]);

    let service = Service {
        metadata: ObjectMeta {
            name: Some(service_name.clone()),
            namespace: Some(namespace.clone()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![ddos.controller_owner_ref(&()).unwrap()]),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(labels),
            ports: Some(vec![
                ServicePort {
                    name: Some("http".to_string()),
                    port: 8080,
                    target_port: Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(8080)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("metrics".to_string()),
                    port: 9090,
                    target_port: Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(9090)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let api: Api<Service> = Api::namespaced(client.clone(), &namespace);
    api.patch(
        &service_name,
        &PatchParams::apply("pistonprotection-operator"),
        &Patch::Apply(&service),
    )
    .await
    .map_err(Error::KubeError)?;

    Ok(())
}

/// Create or update the ConfigMap with backend configuration
pub async fn reconcile_configmap(
    client: &Client,
    ddos: &DDoSProtection,
) -> Result<(), Error> {
    let name = ddos.name_any();
    let namespace = ddos.namespace().unwrap_or_default();
    let configmap_name = format!("{}-config", name);

    info!("Reconciling configmap {}/{}", namespace, configmap_name);

    // Serialize backend configuration
    let backends_json = serde_json::to_string_pretty(&ddos.spec.backends)
        .map_err(Error::SerializationError)?;

    let config_data = BTreeMap::from([
        ("backends.json".to_string(), backends_json),
        ("protection_level".to_string(), ddos.spec.protection_level.to_string()),
    ]);

    let configmap = ConfigMap {
        metadata: ObjectMeta {
            name: Some(configmap_name.clone()),
            namespace: Some(namespace.clone()),
            owner_references: Some(vec![ddos.controller_owner_ref(&()).unwrap()]),
            ..Default::default()
        },
        data: Some(config_data),
        ..Default::default()
    };

    let api: Api<ConfigMap> = Api::namespaced(client.clone(), &namespace);
    api.patch(
        &configmap_name,
        &PatchParams::apply("pistonprotection-operator"),
        &Patch::Apply(&configmap),
    )
    .await
    .map_err(Error::KubeError)?;

    Ok(())
}
