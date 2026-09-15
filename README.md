# Microsoft Sentinel Workbooks — Threat Detection Portfolio

Custom KQL-powered Azure Workbooks built to surface attacker activity that default dashboards miss. Each workbook targets a specific detection gap across network egress, identity, and threat intelligence, and is designed to give an analyst an immediate triage queue rather than raw log noise.

Built and deployed in a live Azure cyber-range environment using `DeviceNetworkEvents`, `NTANetAnalytics`, `SigninLogs`, and `ThreatIntelIndicators`.

---

## Workbooks

### 🌍 Outbound C2 / Beacon Destinations (v1 + v2)

**Files:** `Sudi_-_Outbound_Potential_C2.workbook` · `Sudi_-_Outbound_Potiential_C2_V2.workbook`

Detects potential Command-and-Control (C2) beaconing by mapping outbound connections from `DeviceNetworkEvents` — with Microsoft, Windows, Azure, and M365 destinations stripped by both hostname and IP range.

**Detection logic:** A single external IP contacted by many distinct endpoints (high fan-in) is the C2 signature. The map bubble size = number of distinct devices reaching that destination; color encodes the same metric so hotspots are immediately visible.

**v2 improvements over v1:**
- Dual-layer noise removal: filters by hostname *and* Microsoft IP space (not just URL suffix)
- Tighter thresholds: ≥2 distinct devices AND ≥10 total connections required before a destination appears
- Adds a **connections-per-device** column to distinguish true beaconing from ordinary shared CDN traffic

**Data sources:** `DeviceNetworkEvents`  
**Key fields:** `RemoteIP`, `RemoteUrl`, `DeviceName`, `InitiatingProcessFileName`, `RemotePort`  
**KQL techniques:** `dcount()`, `make_set()`, `geo_info_from_ip_address()`, IP-range filtering, fan-in aggregation

---

### 📤 Potential Exfiltration by Volume

**File:** `Sudi_-_Potential_Exfiltration.workbook`

Catches large outbound data transfers that endpoint-layer tables like MDE cannot show. Uses VNet flow logs from `NTANetAnalytics` to size each external destination by bytes sent (`bytesOut`), then geo-enriches and maps them.

**Detection logic:** A large bubble in an unexpected region = a dominant outbound transfer — the data-exfil signal you won't find in `DeviceNetworkEvents`. The companion table ranks destinations by MB out with source fan-out (how many internal hosts contributed), so a single internal host sending 300 GB to an unusual country stands out immediately.

**Data sources:** `NTANetAnalytics`  
**Key fields:** `DestPublicIps` tuple (`IP|flowStarted|flowEnded|allowedInFlows|deniedInFlows|bytesIn|bytesOut`), `SubType`  
**KQL techniques:** `parse` on structured tuple fields, `geo_info_from_ip_address()`, byte-volume aggregation, `SubType == "FlowLog"` scoping

---

### 🚨 Allowed Inbound Flows from Threat-Intel IPs

**File:** `Sudi_-_Threat_Intel_Inbound.workbook`

Correlates accepted inbound traffic against the live `ThreatIntelIndicators` feed. Most TI dashboards just show you that a known-bad IP knocked — this one shows you it **got in**.

**Detection logic:** Joins `NTANetAnalytics` (AllowedInFlows > 0) with the active, deduped TI watchlist using `arg_max by Id`. Every bubble is an IP that is *both* on the TI feed *and* successfully sent traffic the network accepted. Bubble size = allowed flows; color = bytes received; Targets column = internal hosts reached.

**Data sources:** `NTANetAnalytics` ⋈ `ThreatIntelIndicators`  
**Key fields:** `SrcIp`, `AllowedInFlows`, `BytesIn`, `Confidence`, `ThreatType`  
**KQL techniques:** `arg_max` deduplication, join across two independent tables, confidence/threat-type enrichment, geo-lookup with city+country resolution requirement

---

### 🔐 Authentication Origin Risk Map

**File:** `Sudi_-_Auth_Origin_Risk_Map.workbook`

Maps Entra ID interactive sign-ins by source IP, scored by a composite `RiskScore` — not raw volume. The biggest bubble is the most dangerous origin, not the busiest office.

**Detection logic:** Buckets each source IP into one of four verdicts — *Normal*, *Success from unusual country*, *Failed auth from unusual country*, *Failed then succeeded (possible compromise)* — using 30-day baseline history to distinguish legitimate travel from novel-country access. Failure reason codes are decoded and surfaced separately, with MFA challenges and "keep me signed in" interrupts excluded to avoid inflating legitimate-user bubbles.

**4 panels:**
1. **Sign-in origin map** — geo bubble map, size & color = RiskScore
2. **Verdict distribution** — pie chart breaking down the IP population by verdict
3. **Source IP breakdown** — ranked table with attempts, successes, failures, risky sign-ins, accounts touched, and apps accessed
4. **Failure reason codes** — decoded `ResultType` table (interrupts and MFA excluded) with user count and source country spread

**Data sources:** `SigninLogs`  
**Key fields:** `IPAddress`, `ResultType`, `LocationDetails`, `UserId`, `AppDisplayName`  
**KQL techniques:** Composite risk scoring, `geo_info_from_ip_address()` with IPv6 fallback to `LocationDetails`, baseline windowing, MFA/interrupt bucketing, `make_set` for account/app enumeration

---

## Skills Demonstrated

| Skill | Where |
|---|---|
| KQL query authoring (aggregation, joins, parsing) | All workbooks |
| Network threat hunting (C2, beaconing, exfiltration) | Outbound C2 v1/v2, Exfiltration |
| Identity threat detection (spray, impossible travel, compromise indicators) | Auth Origin Risk Map |
| Threat intelligence operationalization | TI Inbound |
| Azure Workbook development (maps, grids, piecharts, parameters) | All workbooks |
| Geo-enrichment with `geo_info_from_ip_address()` + MaxMind GeoLite2 | All workbooks |
| MDE (`DeviceNetworkEvents`) and network flow (`NTANetAnalytics`) analysis | Outbound C2, Exfiltration |
| Entra ID / Azure AD sign-in log analysis | Auth Origin Risk Map |

---

## Environment

- **Platform:** Microsoft Sentinel (Azure Log Analytics workspace)
- **Tested against:** Live cyber-range environment (`lognpacific.com` tenant)
- **Deployment:** Import `.workbook` JSON files directly into any Sentinel workspace via *Workbooks → New → Advanced Editor*

---

## Usage

1. Clone or download this repo
2. In the Azure portal, navigate to **Microsoft Sentinel → Workbooks → + New**
3. Click **Advanced Editor** (the `</>` icon)
4. Paste the contents of the `.workbook` file and click **Apply**
5. Select your Log Analytics workspace and set the time range parameter

> **Note:** `NTANetAnalytics` requires the **Traffic Analytics** feature enabled on your NSG flow logs. `ThreatIntelIndicators` requires a connected threat intelligence data connector.

---

*Built by [Sid Taha](https://github.com/suditaha) — Security Analyst | Microsoft Sentinel · KQL · Azure Security*
