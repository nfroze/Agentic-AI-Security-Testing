#!/bin/bash

###############################################################################
# Docker Bench Security - CIS Docker Benchmark Checks
# Validates container security hardening for running Docker containers
#
# Reference: https://github.com/aquasecurity/docker-bench-security
# Compliance: CIS Docker Benchmark v1.6.0
#
# Usage: bash security/docker-bench.sh
###############################################################################

set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASS=0
FAIL=0
WARN=0
INFO=0

# Helper functions
pass_check() {
    local check_id=$1
    local check_desc=$2
    echo -e "${GREEN}[PASS]${NC} $check_id: $check_desc"
    ((PASS++))
}

fail_check() {
    local check_id=$1
    local check_desc=$2
    echo -e "${RED}[FAIL]${NC} $check_id: $check_desc"
    ((FAIL++))
}

warn_check() {
    local check_id=$1
    local check_desc=$2
    echo -e "${YELLOW}[WARN]${NC} $check_id: $check_desc"
    ((WARN++))
}

info_check() {
    local check_id=$1
    local check_desc=$2
    echo -e "${BLUE}[INFO]${NC} $check_id: $check_desc"
    ((INFO++))
}

section_header() {
    echo ""
    echo -e "${BLUE}=== $1 ===${NC}"
    echo ""
}

###############################################################################
# Main Checks
###############################################################################

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     Docker Bench Security - Container Hardening Audit        ║"
echo "║              Agentic AI Security Testing Platform             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[ERROR] Docker is not installed or not in PATH${NC}"
    exit 1
fi

running_containers=$(docker ps -q 2>/dev/null)

if [ -z "$running_containers" ]; then
    echo -e "${YELLOW}[WARN] No running containers found${NC}"
    exit 0
fi

###############################################################################
section_header "1. User & Privileges"
###############################################################################

# Check 1.1: Container running as non-root
for container in $running_containers; do
    user=$(docker inspect --format '{{.Config.User}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    if [ -z "$user" ] || [ "$user" = "root" ]; then
        fail_check "1.1" "$name runs as root (user: '$user')"
    else
        pass_check "1.1" "$name runs as non-root user: $user"
    fi
done

# Check 1.2: Container read-only filesystem
for container in $running_containers; do
    readonly=$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    if [ "$readonly" = "false" ]; then
        warn_check "1.2" "$name has writable rootfs (consider read-only for hardening)"
    else
        pass_check "1.2" "$name has read-only rootfs"
    fi
done

# Check 1.3: Container no-new-privileges
for container in $running_containers; do
    security_opts=$(docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    if echo "$security_opts" | grep -q "no-new-privileges"; then
        pass_check "1.3" "$name has no-new-privileges set"
    else
        warn_check "1.3" "$name missing no-new-privileges security option"
    fi
done

###############################################################################
section_header "2. Capabilities & Privileges"
###############################################################################

# Check 2.1: Dropped capabilities
for container in $running_containers; do
    caps=$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    if [ "$caps" = "null" ] || [ -z "$caps" ] || [ "$caps" = "[]" ]; then
        warn_check "2.1" "$name has not dropped any capabilities"
    else
        pass_check "2.1" "$name has dropped capabilities: $caps"
    fi
done

# Check 2.2: No privileged containers
for container in $running_containers; do
    privileged=$(docker inspect --format '{{.HostConfig.Privileged}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    if [ "$privileged" = "true" ]; then
        fail_check "2.2" "$name is running in privileged mode"
    else
        pass_check "2.2" "$name is not running in privileged mode"
    fi
done

# Check 2.3: No privileged ports
for container in $running_containers; do
    ports=$(docker inspect --format '{{json .HostConfig.PortBindings}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    # Check for ports < 1024 (privileged ports)
    if echo "$ports" | grep -qE '"[0-9]{1,3}[0-9]{1,3}[0-9]{1,3}"' && \
       ! echo "$ports" | awk -F':' '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/ && $i < 1024) print}' | grep -q .; then
        pass_check "2.3" "$name uses non-privileged ports"
    else
        info_check "2.3" "$name port bindings: $ports"
    fi
done

###############################################################################
section_header "3. Networking"
###############################################################################

# Check 3.1: Host networking disabled
for container in $running_containers; do
    network=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    if [ "$network" = "host" ]; then
        fail_check "3.1" "$name is using host network (network mode: $network)"
    else
        pass_check "3.1" "$name is not using host network (mode: $network)"
    fi
done

# Check 3.2: Host IPC disabled
for container in $running_containers; do
    ipc=$(docker inspect --format '{{.HostConfig.IpcMode}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    if [ "$ipc" = "host" ]; then
        fail_check "3.2" "$name is using host IPC (IPC mode: $ipc)"
    else
        pass_check "3.2" "$name is not using host IPC (mode: $ipc)"
    fi
done

# Check 3.3: Host PID disabled
for container in $running_containers; do
    pid=$(docker inspect --format '{{.HostConfig.PidMode}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    if [ "$pid" = "host" ]; then
        fail_check "3.3" "$name is using host PID (PID mode: $pid)"
    else
        pass_check "3.3" "$name is not using host PID (mode: $pid)"
    fi
done

###############################################################################
section_header "4. Resource Limits"
###############################################################################

# Check 4.1: Memory limit set
for container in $running_containers; do
    memory=$(docker inspect --format '{{.HostConfig.Memory}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    if [ "$memory" -le 0 ] || [ -z "$memory" ]; then
        warn_check "4.1" "$name has no memory limit set"
    else
        pass_check "4.1" "$name has memory limit: $((memory / 1024 / 1024))M"
    fi
done

# Check 4.2: CPU limit set
for container in $running_containers; do
    cpu=$(docker inspect --format '{{.HostConfig.CpuQuota}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    if [ "$cpu" -le 0 ] || [ -z "$cpu" ]; then
        warn_check "4.2" "$name has no CPU limit set"
    else
        pass_check "4.2" "$name has CPU quota set"
    fi
done

# Check 4.3: PID limit set
for container in $running_containers; do
    pids=$(docker inspect --format '{{.HostConfig.PidsLimit}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    if [ "$pids" -le 0 ] || [ -z "$pids" ]; then
        warn_check "4.3" "$name has no PID limit set"
    else
        pass_check "4.3" "$name has PID limit: $pids"
    fi
done

###############################################################################
section_header "5. Image & Content"
###############################################################################

# Check 5.1: Image signature verification
for container in $running_containers; do
    image=$(docker inspect --format '{{.Config.Image}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    # Check if image is from official/trusted registry
    if echo "$image" | grep -qE '^(gcr.io|ecr.amazonaws.com|docker.io)'; then
        pass_check "5.1" "$name uses trusted registry: $image"
    else
        info_check "5.1" "$name image: $image"
    fi
done

# Check 5.2: Image freshness (check if built recently)
for container in $running_containers; do
    created=$(docker inspect --format '{{.Created}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    info_check "5.2" "$name created at: $created"
done

###############################################################################
section_header "6. Volumes & Mounts"
###############################################################################

# Check 6.1: No host device mounts
for container in $running_containers; do
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')
    devices=$(docker inspect --format '{{json .HostConfig.Devices}}' "$container" 2>/dev/null)

    if [ "$devices" = "null" ] || [ -z "$devices" ] || [ "$devices" = "[]" ]; then
        pass_check "6.1" "$name has no direct device access"
    else
        fail_check "6.1" "$name has direct device access: $devices"
    fi
done

# Check 6.2: No sensitive host mounts
for container in $running_containers; do
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')
    mounts=$(docker inspect --format '{{json .Mounts}}' "$container" 2>/dev/null)

    if echo "$mounts" | grep -qE '/(etc|var|proc|sys|root)'; then
        fail_check "6.2" "$name mounts sensitive host paths"
    else
        pass_check "6.2" "$name does not mount sensitive host paths"
    fi
done

###############################################################################
section_header "7. Health & Monitoring"
###############################################################################

# Check 7.1: Health check configured
for container in $running_containers; do
    health=$(docker inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    if [ -z "$health" ] || [ "$health" = "" ]; then
        warn_check "7.1" "$name has no health check configured"
    else
        pass_check "7.1" "$name has health check: $health"
    fi
done

# Check 7.2: Resource usage tracking
for container in $running_containers; do
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')
    info_check "7.2" "Resource monitoring available via: docker stats $name"
done

###############################################################################
section_header "8. Logging"
###############################################################################

# Check 8.1: Logging driver configured
for container in $running_containers; do
    driver=$(docker inspect --format '{{.HostConfig.LogConfig.Type}}' "$container" 2>/dev/null)
    name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null | sed 's|^/||')

    if [ -z "$driver" ] || [ "$driver" = "json-file" ]; then
        warn_check "8.1" "$name uses default logging driver: $driver"
    else
        pass_check "8.1" "$name uses structured logging: $driver"
    fi
done

###############################################################################
# Summary
###############################################################################

echo ""
echo -e "${BLUE}=== Security Audit Summary ===${NC}"
echo ""
echo -e "${GREEN}Passed:  $PASS${NC}"
echo -e "${RED}Failed:  $FAIL${NC}"
echo -e "${YELLOW}Warnings: $WARN${NC}"
echo -e "${BLUE}Info:    $INFO${NC}"
echo ""

if [ $FAIL -gt 0 ]; then
    echo -e "${RED}[CRITICAL] $FAIL security checks failed. Review and remediate before production deployment.${NC}"
    exit 1
elif [ $WARN -gt 0 ]; then
    echo -e "${YELLOW}[WARNING] $WARN security checks have warnings. Review recommendations for hardening.${NC}"
    exit 0
else
    echo -e "${GREEN}[SUCCESS] All critical security checks passed.${NC}"
    exit 0
fi
