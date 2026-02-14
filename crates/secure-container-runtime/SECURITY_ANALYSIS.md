# Security Analysis — Secure Container Runtime

## Executive Summary

The `secure-container-runtime` crate isolates Docker socket access and enforces
security policies for **validator deployment infrastructure only**.

> **Important:** Challenge execution no longer uses Docker containers.  All
> challenge workloads run inside the deterministic WASM sandbox provided by the
> `wasm-runtime` crate.  This crate is retained exclusively for deploying and
> managing validator service containers (e.g. the validator node itself, helper
> services, monitoring).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PLATFORM VALIDATOR                                  │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    Docker Host                                       │   │
│  │  ┌─────────────────┐    ┌─────────────────┐                         │   │
│  │  │ Container Broker │    │    Validator     │                        │   │
│  │  │  (privileged)    │    │  (no docker.sock)│                       │   │
│  │  │                  │    │                  │                        │   │
│  │  │  /var/run/       │    │                  │                        │   │
│  │  │  docker.sock     │◄───│ Unix Socket API  │                       │   │
│  │  └────────┬─────────┘    └─────────────────┘                        │   │
│  │           │                                                          │   │
│  │           │         platform-network (isolated bridge)               │   │
│  │           └──────────────────────────────────────────────┐          │   │
│  │                                                           │          │   │
│  │           ┌───────────────────────────────────────────────┘          │   │
│  │           │         Isolated Deployment Network                      │   │
│  │           │    (internal=true, no internet by default)               │   │
│  │           └──────────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    WASM Sandbox (wasm-runtime)                        │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
│  │  │ Challenge A   │  │ Challenge B   │  │ Challenge C   │              │   │
│  │  │ (WASM module) │  │ (WASM module) │  │ (WASM module) │              │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │   │
│  │  Deterministic • Memory-safe • No Docker • No filesystem             │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Scope Clarification

| Use-case                         | Runtime              | Notes                                  |
|----------------------------------|----------------------|----------------------------------------|
| Validator node deployment        | Docker (this crate)  | Managed via broker                     |
| Service containers (monitoring)  | Docker (this crate)  | Managed via broker                     |
| Challenge execution              | WASM (`wasm-runtime`)| Sandboxed, deterministic               |
| Challenge internet access        | WASM host functions  | Controlled by `wasm-runtime` imports   |
| Miner submission evaluation      | WASM (`wasm-runtime`)| No Docker involvement                  |

## Threat Model

### Assets to Protect
1. **Docker Daemon** — Full control of host system
2. **Host Filesystem** — Sensitive data, credentials, system files
3. **Network** — Inter-container communication, internet access
4. **Validator Keys** — Cryptographic keys for Bittensor signing
5. **Other Containers** — Isolation between deployment services

### Threat Actors
1. **Compromised Container Images** — Supply chain attacks on deployment images
2. **Network Attackers** — Intercepting inter-container traffic
3. **Insider Threats** — Unauthorized deployment of rogue services

> **Note:** Malicious challenge code is no longer a threat to this crate because
> challenge execution happens entirely within the WASM sandbox.  Challenge
> isolation is the responsibility of `wasm-runtime`.

## Security Controls

### 1. Docker Socket Isolation

**Risk**: Direct access to Docker socket = root on host

**Mitigation**:
- Only the `container-broker` process has Docker socket access
- Deployment containers NEVER receive Docker socket
- Validator components communicate via Unix socket API

**Implementation**:
```rust
if mount.source.contains("docker.sock") && !self.allow_docker_socket {
    return Err(ContainerError::PolicyViolation(
        "Docker socket mounting is not allowed".to_string()
    ));
}
```

### 2. Image Whitelisting

**Risk**: Malicious container images executing arbitrary code

**Mitigation**:
- Only images from `ghcr.io/platformnetwork/` are allowed by default
- Strict mode limits to the Platform registry exclusively
- All other registries are blocked in production

**Blocked Examples**:
- `alpine:latest` ❌
- `ubuntu:22.04` ❌
- `docker.io/malicious/miner:latest` ❌
- `ghcr.io/platformnetwork/validator:latest` ✓

### 3. Non-Privileged Containers

**Risk**: Privileged containers can escape to host

**Mitigation**:
- `privileged: false` always enforced
- All capabilities dropped except minimal set
- `no-new-privileges` security option

### 4. Resource Limits

**Risk**: Resource exhaustion attacks (DoS)

**Mitigation**:
- Memory limits (default 2GB, max 8GB)
- CPU limits (default 1 core, max 4 cores)
- PID limits (default 256, max 512) — prevents fork bombs

### 5. Filesystem Protection

**Risk**: Access to sensitive host files

**Mitigation**:
- Forbidden paths blocklist (`/etc/passwd`, `/etc/shadow`, `/root`, `/proc`, `/sys`, `/dev`)
- Allowed mount prefix whitelist (`/tmp/`, `/var/lib/platform/`, `/var/lib/docker/volumes/`)
- Path traversal detection and prevention
- Read-only mounts encouraged

### 6. Network Isolation

**Risk**: Network attacks between containers or to external services

**Mitigation**:
- Isolated Docker network for deployment services
- No internet access by default
- Network modes: `none`, `bridge`, `isolated`

### 7. Container Tagging & Audit Logging

**Risk**: Orphaned containers, accountability issues

**Mitigation**:
- All containers tagged with service and owner metadata
- Platform-managed label for tracking
- Audit logging of all operations
- Stale container cleanup on broker restart

## Challenge Execution Security (WASM)

Challenge execution security is **out of scope** for this crate.  The
`wasm-runtime` crate provides:

- **Memory isolation** — Each WASM module has its own linear memory
- **Deterministic execution** — Same inputs always produce same outputs
- **No filesystem access** — Challenges cannot read/write host files
- **Controlled network** — Internet access only via explicit host function imports
- **Resource metering** — Fuel-based execution limits prevent infinite loops
- **No container escapes** — There is no container to escape from

## Remaining Risks & Recommendations

### Medium Risk

1. **Container Image Vulnerabilities**
   - Risk: Deployment images may contain CVEs
   - Recommendation: Implement image scanning before deployment
   - Recommendation: Regular base image updates

2. **Audit Log Storage**
   - Risk: Logs only in memory, lost on restart
   - Recommendation: Persistent audit log storage
   - Recommendation: Integration with external SIEM

### Low Risk

1. **Timing Attacks**
   - Risk: CPU timing side-channels between deployment containers
   - Recommendation: Consider CPU isolation if critical

2. **Disk I/O Exhaustion**
   - Risk: No disk quota enforcement currently
   - Recommendation: Implement disk quotas for deployment containers

## Compliance Checklist

| Control                    | Status | Notes                                   |
|----------------------------|--------|-----------------------------------------|
| Docker socket isolation    | ✅     | Via broker architecture                 |
| Image whitelisting         | ✅     | `ghcr.io/platformnetwork/` only         |
| Non-privileged containers  | ✅     | `privileged=false` enforced             |
| Capability dropping        | ✅     | `CAP_DROP=ALL`                          |
| no-new-privileges          | ✅     | Prevents setuid                         |
| Memory limits              | ✅     | Configurable, max 8GB                   |
| CPU limits                 | ✅     | Configurable, max 4 cores               |
| PID limits                 | ✅     | Prevents fork bombs                     |
| Filesystem protection      | ✅     | Forbidden paths blocklist               |
| Network isolation          | ✅     | Internal network, no internet           |
| Container tagging          | ✅     | Service/owner labels                    |
| Audit logging              | ✅     | All operations logged                   |
| Challenge isolation (WASM) | ✅     | Handled by `wasm-runtime` crate         |

## Conclusion

The `secure-container-runtime` provides defense-in-depth security for
**validator deployment infrastructure**:

1. **Isolation** — Docker socket never exposed to services
2. **Whitelisting** — Only trusted images allowed
3. **Hardening** — Non-privileged, capability-dropped containers
4. **Limits** — Resource exhaustion prevented
5. **Auditing** — Full operation logging

Challenge execution is handled entirely by the WASM sandbox (`wasm-runtime`),
which provides stronger isolation guarantees than containers and enables
deterministic, reproducible evaluation across all validators in the P2P network.
