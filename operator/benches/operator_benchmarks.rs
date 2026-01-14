//! Benchmarks for the PistonProtection Operator

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use prometheus::Encoder;

fn reconciliation_benchmark(c: &mut Criterion) {
    c.bench_function("crd_serialization", |b| {
        b.iter(|| {
            // Benchmark CRD serialization
            let value = serde_json::json!({
                "apiVersion": "pistonprotection.io/v1alpha1",
                "kind": "DDoSProtection",
                "metadata": {
                    "name": "test",
                    "namespace": "default"
                },
                "spec": {
                    "backends": [{
                        "name": "backend-1",
                        "address": "10.0.0.1:8080",
                        "protocol": "tcp"
                    }],
                    "replicas": 3,
                    "protectionLevel": 3
                }
            });
            black_box(serde_json::to_string(&value).unwrap())
        })
    });
}

fn validation_benchmark(c: &mut Criterion) {
    c.bench_function("ip_validation", |b| {
        b.iter(|| {
            let ips = vec!["10.0.0.1", "192.168.1.0/24", "2001:db8::1", "invalid"];
            for ip in &ips {
                black_box(ip.parse::<std::net::IpAddr>().is_ok());
            }
        })
    });
}

fn metrics_benchmark(c: &mut Criterion) {
    c.bench_function("metrics_encoding", |b| {
        let registry = prometheus::Registry::new();
        let counter = prometheus::IntCounter::new("test_counter", "Test counter").unwrap();
        registry.register(Box::new(counter.clone())).unwrap();

        b.iter(|| {
            counter.inc();
            let mut buffer = Vec::new();
            let encoder = prometheus::TextEncoder::new();
            let metrics = registry.gather();
            encoder.encode(&metrics, &mut buffer).unwrap();
            black_box(buffer)
        })
    });
}

criterion_group!(
    benches,
    reconciliation_benchmark,
    validation_benchmark,
    metrics_benchmark
);
criterion_main!(benches);
