# goscanner

`goscanner` is an agentless network discovery and asset inventory tool that scans configurable IP ranges, fingerprints the reachable devices, and pushes normalized assets into GLPI via its native inventory API. It is designed to run from a central scanner VM and scales to multiple sites by combining lightweight discovery workers with profile-driven configuration.
`goscanner` is an agentless network discovery and asset inventory tool that scans configurable IP ranges, fingerprints the reachable devices, and pushes normalized assets into GLPI via its native inventory API. It is designed to run from a central scanner VM and scales to multiple sites by combining lightweight discovery workers with profile-driven configuration.

## Features

- **Configurable discovery profiles** – assign custom port sets, worker pools, and timeouts per range or site
- **Agentless liveness detection** – TCP SYN dialing against well-known service ports to identify active hosts
- **Advanced fingerprinting** – Multi-method device identification using:
  - **SNMP** – Query system information, detect printers, copiers, network equipment, and extract vendor/model details
  - **HTTP/HTTPS** – Web server detection and banner grabbing
  - **Port-based classification** – Intelligent device type detection based on open port patterns
- **MAC address collection** – Automatic MAC address retrieval via ARP table lookup for same-subnet devices
- **Enhanced device support** – Comprehensive detection for:
  - **Computers** (Windows, Linux, servers)
  - **Printers** (network printers, laser, inkjet)
  - **Copiers & MFPs** (multifunction peripherals)
  - **Network equipment** (switches, routers, access points)
- **GLPI integration** – Native inventory API client with:
  - OAuth 2.0 authentication (client credentials grant)
  - Legacy API token support
  - Automatic token refresh
  - Retry logic with exponential backoff
  - Full compliance with GLPI 10.0+ inventory format
- **Scheduler-ready** – reusable scheduler component for periodic scans plus a CLI for ad-hoc runs
- **Docker-friendly** – optimized for containerized GLPI deployments with network scanning across subnets
- **Configurable discovery profiles** – assign custom port sets, worker pools, and timeouts per range or site
- **Agentless liveness detection** – TCP SYN dialing against well-known service ports to identify active hosts
- **Advanced fingerprinting** – Multi-method device identification using:
  - **SNMP** – Query system information, detect printers, copiers, network equipment, and extract vendor/model details
  - **HTTP/HTTPS** – Web server detection and banner grabbing
  - **Port-based classification** – Intelligent device type detection based on open port patterns
- **MAC address collection** – Automatic MAC address retrieval via ARP table lookup for same-subnet devices
- **Enhanced device support** – Comprehensive detection for:
  - **Computers** (Windows, Linux, servers)
  - **Printers** (network printers, laser, inkjet)
  - **Copiers & MFPs** (multifunction peripherals)
  - **Network equipment** (switches, routers, access points)
- **GLPI integration** – Native inventory API client with:
  - OAuth 2.0 authentication (client credentials grant)
  - Legacy API token support
  - Automatic token refresh
  - Retry logic with exponential backoff
  - Full compliance with GLPI 10.0+ inventory format
- **Scheduler-ready** – reusable scheduler component for periodic scans plus a CLI for ad-hoc runs
- **Docker-friendly** – optimized for containerized GLPI deployments with network scanning across subnets

## Project layout

```
cmd/goscanner       # CLI entrypoint
pkg/config          # YAML configuration loader
pkg/discovery       # CIDR expansion and liveness engine
pkg/fingerprint     # Host fingerprint modules
pkg/glpi            # REST API client
pkg/inventory       # Asset model + normalizer
pkg/logging         # Logger factory
pkg/scheduler       # Periodic task runner
```

## Quick start

### 1. Build the scanner

```bash
go build -o goscanner ./cmd/goscanner
```

### 2. Configure the scanner

Copy the sample configuration file and update it for your environment:
### 1. Build the scanner

```bash
go build -o goscanner ./cmd/goscanner
```

### 2. Configure the scanner

Copy the sample configuration file and update it for your environment:

```bash
cp goscanner.example.yaml goscanner.yaml
```

Edit `goscanner.yaml` to configure:
- GLPI connection details (URL and authentication)
- Network ranges to scan (CIDR notation)
- Discovery profiles (ports, timeouts, worker pools)
- SNMP community strings (for enhanced device detection)

### 3. Run a network scan

**Scan all configured ranges:**
```bash
./goscanner --config goscanner.yaml --command scan
```

**Scan a specific CIDR range:**
```bash
./goscanner --config goscanner.yaml --command scan --range "192.168.1.0/24"
```

**List configured ranges without scanning:**
```bash
./goscanner --config goscanner.yaml --command list
```

### 4. Review results

The scanner will:
1. **Discover** live hosts by testing configured ports
2. **Fingerprint** each device using SNMP, HTTP/HTTPS, and port analysis
3. **Classify** devices as Computer, Printer, NetworkEquipment, etc.
4. **Push** inventory data to GLPI via `/front/inventory.php`
5. **Report** summary statistics (e.g., "discovered 15 assets")

When GLPI credentials are configured, assets are automatically created or updated in your GLPI instance.

## GLPI Configuration

### Setting up OAuth authentication (recommended for GLPI 10.0+)

The scanner uses OAuth 2.0 client credentials grant for secure authentication with GLPI's native inventory API.

**In GLPI:**
1. Navigate to **Setup → General → API**
2. Ensure the API is enabled
3. Navigate to **Setup → OAuth Clients**
4. Click **Add** to create a new OAuth client:
   - **Name:** `goscanner` (or your preferred name)
   - **Client ID:** Generate or specify (e.g., `scanner`)
   - **Client Secret:** Generate and **copy immediately** (shown only once)
   - **Grant Type:** Select `Client Credentials`
   - **Scopes:** Select `api` (required for inventory submission)
5. Save the client

**In goscanner.yaml:**
```yaml
glpi:
  base_url: "https://your-glpi-server.com/api.php/v2.1"
  mode: jsonapi
  oauth:
    client_id: "scanner"
    client_secret: "YOUR_CLIENT_SECRET_HERE"
    username: "glpi"
    password: ""  # Leave empty to be prompted at runtime (more secure)
    scope: "api"
```

### Using legacy API tokens (GLPI 9.x)

For older GLPI versions, you can use API tokens instead:

**In GLPI:**
1. Navigate to **Setup → General → API**
2. Enable REST API and note the **App-Token** (if required)
3. Navigate to **Users → [your user] → Remote access keys**
4. Generate an **API token**

**In goscanner.yaml:**
```yaml
glpi:
  base_url: "https://your-glpi-server.com/apirest.php"
  mode: legacy
  app_token: "YOUR_APP_TOKEN"    # Optional, only if enforced
  user_token: "YOUR_USER_TOKEN"  # Required
```

### Authentication selection

The scanner automatically detects which authentication method to use:
- If `oauth.client_id`, `oauth.client_secret`, and `oauth.username` are set → OAuth 2.0
- If `user_token` is set → Legacy API tokens
- Authentication tokens are cached and automatically refreshed when expired

## Network scanning configuration

### Defining scan ranges

Network ranges are defined in CIDR notation in `goscanner.yaml`:

```yaml
sites:
  - name: "Headquarters"
    ranges:
      - cidr: "192.168.1.0/24"
        profile: default
        frequency: 1h
      - cidr: "10.0.10.0/24"
        profile: fast_scan
        frequency: 30m
    blacklist:
      - "192.168.1.1"      # Gateway
      - "192.168.1.254"    # Infrastructure device
```

### Discovery profiles

Profiles control how scanning is performed:

```yaml
profiles:
  default:
    description: "Full discovery with SNMP"
    ports: [22,80,443,135,139,445,3389,161,515,9100]
    max_workers: 128
    timeout_ms: 800

  fast_scan:
    description: "Quick ping-only scan"
    ports: [80,443]
    max_workers: 256
    timeout_ms: 500
```

**Port selection guide:**
- `22` - SSH (Linux/Unix servers)
- `80,443` - HTTP/HTTPS (web servers, printers, copiers)
- `135,139,445` - Windows (SMB, RPC)
- `3389` - RDP (Windows Remote Desktop)
- `161` - SNMP (network devices, printers, copiers) - **highly recommended**
- `515,9100` - Printer protocols (LPD, JetDirect)

### SNMP configuration

SNMP provides the most accurate device identification. Configure community strings:

```yaml
credentials:
  - name: "snmp"
    type: snmp
    community: public  # Default community string
```

For enhanced security, use SNMPv3 (future enhancement) or restrict SNMP access by source IP.

## Where scan results appear in GLPI

### Viewing discovered assets

After a successful scan, assets are created or updated in GLPI based on their type:

**1. Computers** (`Assets → Computers`)
- Discovered Windows PCs, Linux servers, workstations
- Contains: hostname, IP address, MAC address, OS information, network interfaces
- Location: **Assets → Computers** menu

**2. Printers** (`Assets → Printers`)
- Network printers (HP, Canon, Epson, Brother, etc.)
- Contains: printer name, IP address, MAC address, serial number
- Location: **Assets → Printers** menu

**3. Network Equipment** (`Assets → Network Equipment`)
- Switches, routers, access points, firewalls
- Contains: device name, IP address, MAC address, model, vendor
- Location: **Assets → Networking** menu

**4. Peripherals** (`Assets → Computers` with type "Peripheral")
- Multifunction copiers, MFPs, and other devices
- Contains: device name, IP address, vendor, model information
- Location: **Assets → Computers** menu (filtered by chassis type)

### Finding your scanned devices

1. **By IP Address:**
   - Navigate to **Assets → [Asset Type]**
   - Use the search box to filter by IP address
   - Example: search for "192.168.1.100"

2. **By MAC Address:**
   - Navigate to the asset type
   - Go to **Network** tab for the asset
   - MAC addresses are stored in network interface information

3. **By Device Name:**
   - Use the global search bar (top right)
   - Enter the hostname discovered via SNMP or reverse DNS
   - Results grouped by asset type

4. **Recent Inventory:**
   - Navigate to **Administration → Inventory**
   - Filter by date to see recently discovered devices
   - Shows all inventory submissions including from goscanner

### Inventory data details

For each asset, goscanner provides:

**Computer assets:**
- Hardware name (from SNMP sysName or hostname)
- Operating system (detected via SNMP or port analysis)
- Network interfaces with IP and MAC addresses
- Open ports (stored in asset attributes)

**Printer assets:**
- Printer name
- IP address and MAC address
- Vendor and model (from SNMP)
- Serial number (if available via SNMP)

**Network equipment:**
- Device name and type
- IP address and MAC address
- Vendor, model, firmware version (from SNMP)
- Management information

### Preventing duplicates

goscanner uses a unique device identifier for each asset:
- Primary: **MAC address** (most reliable)
- Fallback: **IP address** (for devices without MAC)
- Tertiary: **Serial number** (from SNMP)

GLPI's inventory system automatically matches existing assets by deviceid and updates them instead of creating duplicates.

## Docker and containerized GLPI

### Quick Start with Docker Compose

The easiest way to set up GLPI for testing with goscanner is using Docker Compose with the official GLPI image:

**1. Create docker-compose.yml:**

```yaml
version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: glpi-mysql
    command: --default-authentication-plugin=mysql_native_password
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: glpidb
      MYSQL_USER: glpi
      MYSQL_PASSWORD: glpipassword
    volumes:
      - glpi-mysql-data:/var/lib/mysql
    networks:
      - glpi-network
    restart: unless-stopped

  glpi:
    image: diouxx/glpi:latest
    container_name: glpi-app
    ports:
      - "80:80"
    environment:
      TIMEZONE: Europe/Paris
    depends_on:
      - mysql
    networks:
      - glpi-network
    restart: unless-stopped

networks:
  glpi-network:
    driver: bridge

volumes:
  glpi-mysql-data:
```

**2. Start the containers:**

```bash
docker compose up -d
```

**3. Complete GLPI installation:**

Wait about 2 minutes for GLPI to initialize, then navigate to `http://localhost` and follow the installation wizard:

- **Language**: Select your preferred language
- **License**: Accept the license
- **Database setup**:
  - SQL server: `mysql` (the Docker service name)
  - SQL user: `glpi`
  - SQL password: `glpipassword`
  - Database: `glpidb`
- **Complete the installation steps**
- **Default login**: `glpi/glpi` (change password after first login)

**4. Configure GLPI for goscanner:**

After logging in:
- Navigate to **Setup → General → API**
- Enable the REST API
- Set up OAuth client or API tokens as described in the "GLPI Configuration" section above

### Network considerations

**Scanner placement:**
- Run goscanner on the **Docker host** or a VM with network access to target subnets
- The scanner must reach both GLPI (via HTTP/HTTPS) and target devices (via configured ports)

**Cross-subnet scanning:**

If scanning multiple VLANs or subnets:
- Ensure firewall rules allow scanner → target devices on configured ports
- Enable IP forwarding on the Docker host if needed
- For SNMP, ensure UDP port 161 is reachable across subnets

**Scanner configuration for Docker:**

```yaml
glpi:
  # Use Docker host IP or localhost if running on same machine
  base_url: "http://localhost/apirest.php"
  mode: legacy
  user_token: "YOUR_USER_TOKEN_HERE"
  # Or use OAuth for GLPI 10.0+:
  # base_url: "http://localhost/api.php/v2.1"
  # mode: jsonapi
  # oauth:
  #   client_id: "scanner"
  #   client_secret: "YOUR_SECRET_HERE"
  #   username: "glpi"
  #   password: ""
```

### Testing connectivity

Before running scans, verify connectivity:

```bash
# Test GLPI reachability
curl http://localhost

# Test GLPI API (after setup)
curl http://localhost/apirest.php

# Test SNMP to a target device
snmpwalk -v2c -c public 192.168.1.50 .1.3.6.1.2.1.1.1.0

# Test port connectivity
nc -zv 192.168.1.50 161
```

### Troubleshooting Docker setup

**GLPI shows blank page:**
- Wait 2-3 minutes for full initialization
- Check logs: `docker logs glpi-app`
- Restart containers: `docker compose restart`

**Database connection errors:**
- Verify MySQL is running: `docker ps`
- Check MySQL logs: `docker logs glpi-mysql`
- Ensure service name is `mysql` in docker-compose.yml

**Cannot access GLPI from browser:**
- Check if port 80 is already in use: `sudo netstat -tulpn | grep :80`
- Try a different port in docker-compose.yml: `"8080:80"`
- Check Docker network: `docker network inspect glpi-network`

## Logging & troubleshooting

### Logging configuration

Configure logging in `goscanner.yaml`:

```yaml
logging:
  level: debug    # Options: debug, info, warn, error
  path: ""        # Empty = stdout, or specify file path
  format: text    # Options: text, json
```

**Log levels:**
- `debug` - Detailed information including SNMP queries, HTTP requests, every asset processed
- `info` - Summary information (sites, ranges, asset counts, GLPI push results)
- `warn` - Warnings about non-critical issues
- `error` - Errors that prevent asset discovery or GLPI integration

### Common issues

**1. "GLPI authentication failed"**
- Verify OAuth client ID and secret are correct
- Check that the OAuth client has the "api" scope
- Ensure username/password are valid GLPI credentials
- For legacy API: verify user_token is active

**2. "GLPI inventory failed (status 401)"**
- OAuth token expired (should auto-refresh, but check logs)
- User lacks inventory submission permissions
- App token missing (if GLPI requires it)

**3. "No devices discovered"**
- Verify network connectivity to target ranges
- Check firewall rules allow scanner → targets on configured ports
- Try with `logging.level: debug` to see per-host results
- Reduce `timeout_ms` if network is slow

**4. "SNMP queries failing"**
- Verify SNMP is enabled on target devices
- Check community string matches device configuration
- Ensure UDP port 161 is not blocked by firewall
- Try `snmpwalk` command manually to test

**5. "Duplicate assets in GLPI"**
- Check if MAC address collection is working
- Verify GLPI is configured to match devices by MAC/serial
- Review GLPI inventory rules under **Administration → Rules → Inventory**

### Debug mode output example

```
INFO  starting scan run
INFO  site Headquarters
INFO  scanning 192.168.1.0/24 with profile default
DEBUG 192.168.1.0/24 produced 254 host results
DEBUG fingerprinting 192.168.1.10 with 3 open ports
DEBUG SNMP query successful: HP LaserJet Pro MFP M428fdw
DEBUG classified as Printer, vendor HP
INFO  pushing 15 assets to GLPI at https://glpi.local/front/inventory.php
DEBUG glpi upsert successful for 192.168.1.10
INFO  discovered 15 assets
```

## License

This project is licensed under the MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.