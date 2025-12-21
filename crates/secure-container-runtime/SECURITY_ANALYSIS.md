# Security Analysis - Secure Container Runtime

## Executive Summary

This document provides a comprehensive security analysis of the `secure-container-runtime` crate, which isolates Docker socket access and enforces security policies for challenge container management.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PLATFORM VALIDATOR                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    Docker Host                                        │  │
│  │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐  │  │
│  │  │ Container Broker │    │    Validator    │    │   Challenge     │  │  │
│  │  │  (privileged)   │    │  (no docker.sock)│   │   Container     │  │  │
│  │  │                 │    │                 │    │  (isolated)     │  │  │
│  │  │  /var/run/      │    │                 │    │                 │  │  │
│  │  │  docker.sock    │◄───│ Unix Socket API │    │  No docker.sock │  │  │
│  │  └────────┬────────┘    └─────────────────┘    └─────────────────┘  │  │
│  │           │                      │                      │           │  │
│  │           │              platform-challenges network    │           │  │
│  │           └──────────────────────┼──────────────────────┘           │  │
│  │                                  │                                   │  │
│  │           ┌──────────────────────┴──────────────────────┐           │  │
│  │           │         Isolated Challenge Network           │           │  │
│  │           │    (internal=true, no internet by default)   │           │  │
│  │           └─────────────────────────────────────────────┘           │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Threat Model

### Assets to Protect
1. **Docker Daemon** - Full control of host system
2. **Host Filesystem** - Sensitive data, credentials, system files
3. **Network** - Inter-container communication, internet access
4. **Validator Keys** - Cryptographic keys for signing
5. **Other Containers** - Isolation between challenges

### Threat Actors
1. **Malicious Challenge Code** - Submitted by attackers
2. **Compromised Container Images** - Supply chain attacks
3. **Malicious Miners** - Attempting to gain unfair advantages
4. **Network Attackers** - Intercepting inter-container traffic

## Security Controls

### 1. Docker Socket Isolation

**Risk**: Direct access to Docker socket = root on host

**Mitigation**:
- Only the `container-broker` process has Docker socket access
- Challenge containers NEVER receive Docker socket
- Validator container communicates via Unix socket API

**Implementation**:
```rust
// Forbidden mount check
if mount.source.contains("docker.sock") && !self.allow_docker_socket {
    return Err(ContainerError::PolicyViolation(
        "Docker socket mounting is not allowed".to_string()
    ));
}
```

**Verification Test**:
```rust
#[test]
fn test_default_policy_blocks_docker_socket() {
    let policy = SecurityPolicy::default();
    let mounts = vec![MountConfig {
        source: "/var/run/docker.sock".to_string(),
        target: "/var/run/docker.sock".to_string(),
        read_only: true,
    }];
    assert!(policy.validate_mounts(&mounts).is_err());
}
```

### 2. Image Whitelisting

**Risk**: Malicious container images executing arbitrary code

**Mitigation**:
- Only images from `ghcr.io/platformnetwork/` are allowed
- All other registries are blocked

**Implementation**:
```rust
pub fn validate_image(&self, image: &str) -> Result<(), ContainerError> {
    let image_lower = image.to_lowercase();
    for prefix in &self.allowed_image_prefixes {
        if image_lower.starts_with(&prefix.to_lowercase()) {
            return Ok(());
        }
    }
    Err(ContainerError::ImageNotWhitelisted(image.to_string()))
}
```

**Blocked Examples**:
- `alpine:latest` ❌
- `ubuntu:22.04` ❌
- `docker.io/malicious/miner:latest` ❌
- `ghcr.io/platformnetwork/term-challenge:latest` ✓

### 3. Non-Privileged Containers

**Risk**: Privileged containers can escape to host

**Mitigation**:
- `privileged: false` always enforced
- All capabilities dropped except minimal set
- `no-new-privileges` security option

**Implementation**:
```rust
let host_config = HostConfig {
    privileged: Some(false),
    cap_drop: Some(vec!["ALL".to_string()]),
    cap_add: Some(vec![
        "CHOWN".to_string(),
        "SETUID".to_string(),
        "SETGID".to_string(),
    ]),
    security_opt: Some(vec!["no-new-privileges:true".to_string()]),
    ..Default::default()
};
```

### 4. Resource Limits

**Risk**: Resource exhaustion attacks (DoS)

**Mitigation**:
- Memory limits (default 2GB, max 8GB)
- CPU limits (default 1 core, max 4 cores)
- PID limits (default 256, max 512) - prevents fork bombs

**Implementation**:
```rust
pub struct ResourceLimits {
    pub memory_bytes: i64,      // Max: 8GB
    pub cpu_cores: f64,         // Max: 4.0
    pub pids_limit: i64,        // Max: 512
    pub disk_quota_bytes: u64,
}
```

### 5. Filesystem Protection

**Risk**: Access to sensitive host files

**Mitigation**:
- Forbidden paths blocklist
- Allowed mount prefix whitelist
- Read-only mounts encouraged

**Blocked Paths**:
```rust
forbidden.insert("/var/run/docker.sock");
forbidden.insert("/etc/passwd");
forbidden.insert("/etc/shadow");
forbidden.insert("/etc/sudoers");
forbidden.insert("/root");
forbidden.insert("/home");
forbidden.insert("/proc");
forbidden.insert("/sys");
forbidden.insert("/dev");
```

### 6. Network Isolation

**Risk**: Network attacks between containers or to external services

**Mitigation**:
- Isolated Docker network for challenges
- No internet access by default
- Network modes: `none`, `bridge`, `isolated`

**Implementation**:
```rust
// Create isolated network
let config = CreateNetworkOptions {
    name: self.network_name.clone(),
    driver: "bridge".to_string(),
    internal: true,  // No external access
    ..Default::default()
};
```

### 7. Container Tagging

**Risk**: Orphaned containers, accountability issues

**Mitigation**:
- All containers tagged with challenge_id and owner_id
- Platform-managed label for tracking
- Audit logging of all operations

**Labels Applied**:
```rust
labels.insert(labels::CHALLENGE_ID, config.challenge_id.clone());
labels.insert(labels::OWNER_ID, config.owner_id.clone());
labels.insert(labels::CREATED_BY, "secure-container-runtime".to_string());
labels.insert(labels::BROKER_VERSION, BROKER_VERSION.to_string());
labels.insert(labels::MANAGED, "true".to_string());
```

### 8. Audit Logging

**Risk**: Undetected malicious activity

**Mitigation**:
- All container operations logged
- Includes challenge_id, owner_id, success/failure
- Policy violations logged with details

**Audit Entry**:
```rust
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub action: AuditAction,
    pub challenge_id: String,
    pub owner_id: String,
    pub container_id: Option<String>,
    pub success: bool,
    pub error: Option<String>,
    pub details: HashMap<String, String>,
}
```

## Attack Scenarios & Mitigations

### Scenario 1: Container Escape via Docker Socket

**Attack**: Challenge tries to mount Docker socket
```json
{
  "mounts": [{
    "source": "/var/run/docker.sock",
    "target": "/var/run/docker.sock"
  }]
}
```

**Result**: BLOCKED by policy
```
Error: PolicyViolation("Docker socket mounting is not allowed")
```

### Scenario 2: Malicious Image Pull

**Attack**: Pull a cryptominer image
```json
{"type": "pull", "image": "docker.io/xmrig/xmrig:latest"}
```

**Result**: BLOCKED by whitelist
```
Error: ImageNotWhitelisted("docker.io/xmrig/xmrig:latest")
```

### Scenario 3: Fork Bomb

**Attack**: Execute `:(){ :|:& };:` in container

**Result**: MITIGATED by PID limit
- Container limited to 256 PIDs
- Fork bomb fails when limit reached
- Host system unaffected

### Scenario 4: Memory Exhaustion

**Attack**: Allocate infinite memory

**Result**: MITIGATED by memory limit
- Container OOM-killed at 2GB limit
- Host system unaffected

### Scenario 5: Privilege Escalation

**Attack**: Use setuid binary to gain root

**Result**: BLOCKED by security options
- `no-new-privileges` prevents setuid
- All capabilities dropped
- Container runs unprivileged

### Scenario 6: Host Network Scan

**Attack**: Scan host network from container

**Result**: MITIGATED by network isolation
- Container on isolated network
- Cannot reach host services
- Only sees other challenge containers (if any)

### Scenario 7: Access Validator Keys

**Attack**: Mount /root or /home to steal keys

**Result**: BLOCKED by forbidden paths
```
Error: PolicyViolation("Mount path '/root' is forbidden")
```

## Remaining Risks & Recommendations

### Medium Risk

1. **Container Image Vulnerabilities**
   - Risk: Images may contain CVEs
   - Recommendation: Implement image scanning before deployment
   - Recommendation: Regular base image updates

2. **Inter-Challenge Communication**
   - Risk: Challenges on same network can communicate
   - Recommendation: Per-challenge network isolation option
   - Recommendation: Network policies for fine-grained control

3. **Audit Log Storage**
   - Risk: Logs only in memory, lost on restart
   - Recommendation: Persistent audit log storage
   - Recommendation: Integration with external SIEM

### Low Risk

1. **Timing Attacks**
   - Risk: CPU timing side-channels
   - Recommendation: Consider CPU isolation if critical

2. **Disk I/O Exhaustion**
   - Risk: No disk quota enforcement currently
   - Recommendation: Implement disk quotas

## Compliance Checklist

| Control | Status | Notes |
|---------|--------|-------|
| Docker socket isolation | ✅ | Via broker architecture |
| Image whitelisting | ✅ | ghcr.io/platformnetwork/ only |
| Non-privileged containers | ✅ | privileged=false enforced |
| Capability dropping | ✅ | CAP_DROP=ALL |
| no-new-privileges | ✅ | Prevents setuid |
| Memory limits | ✅ | Configurable, max 8GB |
| CPU limits | ✅ | Configurable, max 4 cores |
| PID limits | ✅ | Prevents fork bombs |
| Filesystem protection | ✅ | Forbidden paths blocklist |
| Network isolation | ✅ | Internal network, no internet |
| Container tagging | ✅ | challenge_id, owner_id labels |
| Audit logging | ✅ | All operations logged |

## Test Coverage

```
running 29 tests
test broker::tests::test_broker_creation ... ok
test broker::tests::test_policy_enforcement ... ok
test policy::tests::test_policy_default ... ok
test policy::tests::test_validate_docker_socket_blocked ... ok
test policy::tests::test_validate_image_allowed ... ok
test policy::tests::test_validate_image_blocked ... ok
test policy::tests::test_validate_resources ... ok
test policy::tests::test_validate_full_config ... ok
test policy::tests::test_validate_missing_challenge_id ... ok
test policy::tests::test_policy_blocks_sensitive_mounts ... ok
test policy::tests::test_policy_container_limits ... ok
test test_broker_lifecycle ... ok
test test_broker_blocks_malicious_image ... ok
test test_broker_blocks_docker_socket_mount ... ok
test test_image_pull_whitelist ... ok
... (29 total)

test result: ok. 29 passed; 0 failed
```

## Conclusion

The `secure-container-runtime` provides defense-in-depth security for container management:

1. **Isolation** - Docker socket never exposed to challenges
2. **Whitelisting** - Only trusted images allowed
3. **Hardening** - Non-privileged, capability-dropped containers
4. **Limits** - Resource exhaustion prevented
5. **Auditing** - Full operation logging

The architecture significantly reduces the attack surface compared to direct Docker socket access while maintaining the functionality needed for challenge orchestration.
