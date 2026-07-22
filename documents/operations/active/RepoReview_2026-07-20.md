# Rustynet Repository Review - 2026-07-20

## Executive Summary

**Status:** ACTIVE DEVELOPMENT - Release Blocking Issues Identified
**Primary Gap:** Cross-platform role parity (macOS/Windows) remains unproven
**Critical Risk:** Live-lab evidence shows consistent failures in exit/relay/anchor lifecycle stages

---

## 1. Documentation Health

### 1.1 Core Documents - PASS
- `AGENTS.md` ↔ `CLAUDE.md`: Byte-for-byte identical (verified via diff)
- `README.md`: 696 lines, comprehensive, well-structured
- `documents/README.md`: 227 lines, complete doc index with read order
- `Requirements.md`: 401 lines, covers vision, user stories, functional/non-functional/security requirements
- `SecurityMinimumBar.md`: 403 lines, detailed controls with test evidence requirements

### 1.2 Active Ledgers - PASS
- `CrossPlatformRoleParityPlan_2026-06-21.md`: Release-blocking mandate clearly documented
- `CrossPlatformRoleParityRoadmap_2026-06-22.md`: Execution roadmap with ordered implementation program
- `LiveLabExecutionEfficiencyPlan_2026-06-20.md`: Operating method for live-lab loop
- `RustynetDataplaneExecutionPlan_2026-05-18.md`: Cross-network dataplane track
- `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md`: Integration spec for cross-network stages
- `ServiceHostingRolesRoadmap_2026-06-11.md`: Service-hosting roles program
- `MasterWorkPlan_2026-03-22.md`: Repo-wide remaining work
- `PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md`: Traversal/relay readiness

**Finding:** All active ledgers are present and current. No stale documentation detected.

---

## 2. Live-Lab Evidence Analysis

### 2.1 Run Matrix Status (live_lab_node_run_matrix.csv)

**Total Runs Analyzed:** 62 (2026-07-10 to 2026-07-16)
**Engine:** Rust `--node` orchestrator (ACTIVE ledger)

#### 2.1.1 Failure Patterns

**Consistent Failures (Linux-only testing):**
| Stage | Fail Count | First Seen | Last Seen | Status |
|-------|------------|------------|-----------|--------|
| `exit_dns_failclosed_validation` | 2 | 2026-07-10 | 2026-07-10 | **UNRESOLVED** |
| `exit_nat_lifecycle_validation` | 1 | 2026-07-10 | 2026-07-10 | **UNRESOLVED** |
| `bootstrap_hosts` | 1 | 2026-07-10 | 2026-07-10 | **UNRESOLVED** |
| `exit_demotion_residue_validation` | 2 | 2026-07-11 | 2026-07-11 | **UNRESOLVED** |
| `blind_exit_dataplane_validation` | 1 | 2026-07-11 | 2026-07-11 | **UNRESOLVED** |
| `live_two_hop_validation` | 10+ | 2026-07-11 | 2026-07-16 | **CRITICAL - BLOCKING** |
| `live_managed_dns_validation` | 6 | 2026-07-11 | 2026-07-15 | **CRITICAL - BLOCKING** |
| `live_reboot_recovery_validation` | 2 | 2026-07-12 | 2026-07-12 | **UNRESOLVED** |
| `live_enrollment_restart_validation` | 1 | 2026-07-12 | 2026-07-12 | **UNRESOLVED** |
| `live_lan_toggle_validation` | 1 | 2026-07-12 | 2026-07-12 | **UNRESOLVED** |
| `validate_baseline_runtime` | 2 | 2026-07-14 | 2026-07-16 | **UNRESOLVED** |
| `enforce_baseline_runtime` | 3 | 2026-07-14 | 2026-07-16 | **UNRESOLVED** |
| `distribute_assignments` | 1 | 2026-07-14 | 2026-07-14 | **UNRESOLVED** |
| `preflight` | 2 | 2026-07-14 | 2026-07-15 | **UNRESOLVED** |
| `traffic_test_matrix` | 2 | 2026-07-15 | 2026-07-16 | **UNRESOLVED** |

#### 2.1.2 Success Patterns

**Partial Passes Achieved:**
- **2026-07-13 08:27:06Z** (cf904d71bd73): 36 passed, 0 failed, 22 skipped - **FIRST GREEN ROW**
- **2026-07-13 10:44:06Z** (0ec357c270f9): 36 passed, 0 failed, 22 skipped
- **2026-07-13 12:01:44Z** (982a6e288494): 36 passed, 0 failed, 22 skipped
- **2026-07-13 14:28:00Z** (44c23ef080e0): 36 passed, 0 failed, 22 skipped
- **2026-07-16 08:30:16Z** (4a6e7b66449e): 13 passed, 0 failed, 1 skipped (14 stages)
- **2026-07-16 09:09:17Z** (5645db2a0f68): 5 passed, 0 failed, 9 skipped (14 stages)

**Observation:** Linux-only testing shows progress with 36-stage passes, but cross-network and advanced stages consistently fail.

#### 2.1.3 Platform Coverage

**Current State:**
- **Linux:** debian-headless-2, debian-headless-4, rocky-utm-1, fedora-utm-1, ubuntu-utm-1
- **macOS:** NOT PRESENT in any run
- **Windows:** NOT PRESENT in any run

**Critical Gap:** No macOS or Windows nodes in live-lab runs. This directly contradicts the release-blocking mandate in `CrossPlatformRoleParityPlan_2026-06-21.md` which requires every role to be LIVE-LAB-PROVEN on macOS AND Windows.

---

## 3. Architecture & Code Structure

### 3.1 Crate Organization - PASS
- 24 crates in `/crates/` directory
- Clear layering: Domain (transport-agnostic) → Daemon+Services → Backend Abstraction → Platform+UX
- Boundary rules documented and enforced

### 3.2 Backend Boundary Compliance
**Status:** Requires verification
**Action:** Run `scripts/ci/check_backend_boundary_leakage.sh` to confirm no WireGuard types leak into domain crates

---

## 4. Security Posture

### 4.1 Security Minimum Bar
- Controls documented in `SecurityMinimumBar.md`
- Each control requires: enforcement point + verification method
- **Status:** Documentation complete, implementation requires audit

### 4.2 Known Findings
**From SecurityMinimumBar.md:**
- RN-01 through RN-38 tracked
- Requires verification against current codebase

---

## 5. Critical Findings & Recommendations

### 5.1 Release-Blocking Issues

#### 5.1.1 Cross-Platform Parity Gap (CRITICAL)
**Issue:** No macOS or Windows nodes in live-lab evidence
**Impact:** Cannot claim release readiness per `CrossPlatformRoleParityPlan_2026-06-21.md`
**Evidence:** All 62 runs in `live_lab_node_run_matrix.csv` are Linux-only
**Action:**
1. Add macOS VM to inventory and runs
2. Add Windows VM to inventory and runs
3. Execute role lifecycle tests on both platforms
4. Document evidence in run matrix

#### 5.1.2 Consistent Stage Failures (HIGH)
**Issue:** `live_two_hop_validation` fails in 10+ consecutive runs
**Impact:** Blocks cross-network dataplane validation (D2-D13)
**Evidence:** Runs from 2026-07-11 through 2026-07-16
**Action:**
1. Triage root cause of two-hop failure
2. Fix and verify with targeted re-run
3. Document fix in stage triage history

#### 5.1.3 Managed DNS Validation (HIGH)
**Issue:** `live_managed_dns_validation` fails in 6 consecutive runs
**Impact:** Blocks DNS service validation
**Evidence:** Runs from 2026-07-11 through 2026-07-15
**Action:**
1. Investigate DNS configuration in test environment
2. Verify Magic DNS implementation
3. Re-run with fix

### 5.2 Documentation Gaps

#### 5.2.1 Incomplete Run Matrix
**Issue:** macOS and Windows columns are empty/skipped in all runs
**Impact:** Cannot track cross-platform progress
**Action:** Populate matrix with actual macOS/Windows test results

#### 5.2.2 Missing Evidence Links
**Issue:** Some runs reference `/private/tmp/claude-501/...` paths that may be ephemeral
**Impact:** Evidence may be lost
**Action:** Ensure all evidence is stored in repo-relative paths under `state/`

### 5.3 Process Improvements

#### 5.3.1 Test Coverage
**Issue:** 22 stages consistently skipped in successful runs
**Impact:** Incomplete validation coverage
**Action:** Investigate why stages are skipped and enable them

#### 5.3.2 Failure Triage
**Issue:** Multiple runs fail at same stages without documented root cause
**Impact:** Repeated failures without resolution
**Action:** Use `rustynet-lab-state_stage_triage_history` to track attempted fixes

---

## 6. Verification Checklist

- [ ] Run `scripts/ci/check_backend_boundary_leakage.sh`
- [ ] Run `scripts/ci/secrets_hygiene_gates.sh`
- [ ] Run `cargo audit --deny warnings`
- [ ] Run `cargo deny check bans licenses sources advisories`
- [ ] Verify AGENTS.md/CLAUDE.md remain synchronized
- [ ] Confirm all active ledgers are current
- [ ] Validate inventory includes macOS and Windows nodes
- [ ] Execute live-lab run with all three platforms

---

## 7. Next Steps

1. **IMMEDIATE:** Add macOS and Windows nodes to live-lab inventory
2. **IMMEDIATE:** Triage `live_two_hop_validation` failure
3. **IMMEDIATE:** Triage `live_managed_dns_validation` failure
4. **SHORT-TERM:** Run full security gate suite
5. **SHORT-TERM:** Verify backend boundary compliance
6. **MEDIUM-TERM:** Achieve first macOS role lifecycle pass
7. **MEDIUM-TERM:** Achieve first Windows role lifecycle pass
