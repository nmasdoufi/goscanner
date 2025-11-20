# Understanding GLPI Network Ports vs. TCP Service Ports

## The Issue

After extensive research into GLPI's inventory format and API, I discovered an important limitation:

**GLPI's "Network Ports" tab is for PHYSICAL network interfaces, NOT for open TCP service ports.**

## What GLPI Network Ports Actually Are

The "Network Ports" section in GLPI (`computer.form.php → Network Ports`) displays:

- **Physical network adapters** (eth0, wlan0, en0, etc.)
- **Network interface details**:
  - ifname (interface name)
  - ifnumber (interface index)
  - ifstatus (up/down/dormant)
  - ifspeed, ifmtu, iftype
  - MAC address
  - IP addresses
  - Traffic metrics (bytes in/out, errors)
  - VLAN information
  - Port aggregation
  - CDP/LLDP connections to switches

**Examples:**
- "eth0 - Ethernet Adapter - 192.168.1.50 - Up"
- "wlan0 - Wireless Adapter - 10.0.0.100 - Connected to SSID"

## What GLPI Network Ports Are NOT

GLPI's Network Ports do NOT store:
- ❌ Open TCP/UDP service ports (22/SSH, 80/HTTP, 443/HTTPS, etc.)
- ❌ Listening services discovered by port scanning
- ❌ Network service enumeration
- ❌ Vulnerability assessment data

## Why This Matters

GLPI is primarily designed for **SNMP-based hardware inventory**, not for **network security scanning**.

The official GLPI Agent uses:
- SNMP queries for device information
- WMI/SSH for computer details
- CDP/LLDP for network topology
- **NOT Nmap-style port scanning**

## What We're Actually Discovering

goscanner performs network reconnaissance that includes:
- Port scanning (SYN scan for 22, 80, 443, 161, etc.)
- Service identification
- Device fingerprinting

This is **security scanning data** that GLPI's standard inventory format was not designed to handle.

## Current State

✅ **Open ports ARE captured** in `asset.Attributes["open_ports"]`
✅ **Logged during scans** with full visibility
❌ **No standard GLPI field exists** to display this in the UI

## Why network_ports Failed

When we tried adding `network_ports` to the inventory:

```json
{
  "network_ports": [
    {"logical": 22, "name": "SSH (TCP/22)"},
    {"logical": 80, "name": "HTTP (TCP/80)"}
  ]
}
```

**Result:** `500 Internal Server Error`

**GLPI Error:** `"Call to undefined method Glpi\\Inventory\\MainAsset\\Computer::getManagementPorts()"`

**Reason:** GLPI expects network_ports to contain physical interface data (ifname, ifnumber, etc.), not TCP port numbers.

---

## Alternative Solutions

### Option 1: Add to Comments Field (Recommended)

GLPI computers have a `comment` field that accepts free-form text. We can add port information there:

**Advantages:**
- ✅ Visible in GLPI UI immediately
- ✅ Searchable
- ✅ No custom development needed

**Implementation:**
```go
inv.Content.Hardware = &GLPIHardware{
    Name:        asset.Hostname,
    Description: description,
    Comment:     formatOpenPorts(asset.Attributes["open_ports"]),
}

func formatOpenPorts(ports string) string {
    return fmt.Sprintf("Open TCP Ports: %s\nDiscovered by goscanner", ports)
}
```

**What it looks like in GLPI:**
```
Asset Details → Information → Comments
────────────────────────────────────
Open TCP Ports: [22 80 443 161]
Discovered by goscanner on 2025-11-19
```

### Option 2: Use GLPI Custom Fields Plugin

GLPI supports custom fields via the "Additional Fields" plugin:

**Advantages:**
- ✅ Structured data
- ✅ Searchable and filterable
- ✅ Can create dedicated "Security Scan" section

**Requirements:**
- Install GLPI Additional Fields plugin
- Configure custom field for "Open Ports"
- Modify goscanner to use plugin API

**Not currently implemented** - requires additional GLPI configuration.

### Option 3: Store in Software/Services Section

Some GLPI inventory formats support a `processes` array for running services:

**Advantages:**
- ✅ Semantically appropriate (services ARE processes)
- ✅ GLPI understands processes

**Disadvantages:**
- ⚠️ Requires mapping ports to service names
- ⚠️ Only works if service is actually running (not just port open)
- ⚠️ May not appear in expected UI location

### Option 4: Create GLPI Plugin

Develop a custom GLPI plugin that:
- Reads the current open_ports attribute
- Displays in a dedicated "Network Security" tab
- Tracks port changes over time
- Generates alerts on new ports

**Advantages:**
- ✅ Full control over UI/UX
- ✅ Can add security-specific features

**Disadvantages:**
- ❌ Requires PHP development
- ❌ Plugin maintenance
- ❌ Not included in base GLPI

### Option 5: Use External Security Tool Integration

Store scan data in dedicated security tools:
- Nessus
- OpenVAS
- SecurityCenter
- AlienVault OSSIM

Then reference asset IDs between GLPI and security tool.

---

## Recommendation

**For immediate visibility with minimal changes:**

Add open ports to the **Comments field** (Option 1). This provides:
- Quick implementation (5 minutes)
- Immediate visibility in GLPI UI
- Searchable across all assets
- No additional infrastructure

**For long-term solution:**

Consider whether GLPI is the right tool for network security data. GLPI excels at:
- Hardware inventory
- Asset management
- SNMP device monitoring

For security scanning, tools like:
- **Nmap** with XML output
- **OpenVAS** for vulnerability management
- **Wazuh** for security monitoring

May be more appropriate than trying to force security data into an asset management system.

---

## Technical Details: GLPI Inventory Format Schema

From `https://github.com/glpi-project/inventory_format`:

**networks array** - Basic network interface info:
```json
{
  "networks": [{
    "description": "eth0",
    "ipaddress": "192.168.1.50",
    "macaddr": "AA:BB:CC:DD:EE:FF",
    "status": "Up",
    "type": "ethernet"
  }]
}
```

**network_ports array** - Physical interface details:
```json
{
  "network_ports": [{
    "ifname": "eth0",
    "ifnumber": 2,
    "ifstatus": "up",
    "ifspeed": 1000000000,
    "mac": "AA:BB:CC:DD:EE:FF",
    "ips": ["192.168.1.50"],
    "connections": []
  }]
}
```

**No field exists for TCP service ports** in the standard schema.

---

## Summary

1. ✅ **Fixed compilation error** - Removed invalid network_ports code
2. ✅ **Code builds successfully** - No more 500 errors from GLPI
3. ℹ️ **Port data still collected** - Stored in attributes and logs
4. ⚠️ **No standard GLPI field** - Network Ports tab is for physical interfaces
5. 💡 **Suggested solution** - Add to Comments field for visibility

**Next Steps:**
- Choose which alternative solution to implement
- Or accept that GLPI may not be the ideal tool for port scan data
