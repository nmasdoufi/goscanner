# GLPI Inventory Troubleshooting Guide

## Assets Not Appearing in GLPI Dashboard

If you've successfully run a scan but don't see assets in GLPI, follow these steps:

### Step 1: Enable Debug Logging

Edit `pkg/glpi/client.go` and uncomment the debug lines:

```go
// Line ~114: Uncomment to see what's being sent
fmt.Printf("Sending inventory for %s:\n%s\n", asset.IP, string(body))

// Line ~164: Uncomment to see GLPI's response
fmt.Printf("GLPI inventory accepted (status %d): %s\n", resp.StatusCode, string(bodyBytes))
```

Rebuild and run:
```bash
go build -o goscanner ./cmd/goscanner
./goscanner --config goscanner.yaml --command scan
```

This shows the exact JSON being sent and GLPI's response.

### Step 2: Check GLPI Inventory Queue

**Navigate to:** Administration → Inventory

Look for three sections:

1. **Pending inventories**
   - Items waiting to be processed
   - Click to see why they're pending

2. **Refused inventories**
   - Items rejected by rules
   - **This is likely where your assets are!**
   - Click to see rejection reason

3. **Processed inventories**
   - Successfully imported items
   - Check if items are here but not visible

**Common reasons for refusal:**
- No rule matched the inventory
- Required fields missing
- Duplicate detection issues

### Step 3: Fix Inventory Import Rules

The most common issue is incorrect rule configuration.

**Navigate to:** Administration → Rules → Rules for import and link computers

#### Create/Edit Rule:

**Basic Settings:**
- **Name:** Accept goscanner inventory
- **Active:** ✓ Yes
- **Description:** Import all devices from goscanner

**Criteria Tab:**
Leave empty OR add:
- **GLPI version client** | contains | `goscanner`

**Actions Tab (CRITICAL):**
Add these actions:
1. **Computer import** → Assign value: **✓** (checkbox)
2. **Link to computer if possible** → Assign value: **Yes**
3. **Item to link** → Assign value: **Computer**
4. **Entity** → Assign value: **Root entity** (or your entity)

**Rule Order:**
- This rule should be **at the top** of the list
- Drag to reorder if needed

**Save and test!**

### Step 4: Check for "Unmanaged Devices"

If rules aren't working, items might appear as unmanaged devices:

**Navigate to:** Assets → Unmanaged devices

Look for your scanned IPs/MACs here. If found:
- Click the device
- Click **Import** button
- Select device type (Computer, Printer, etc.)
- Choose entity
- Confirm import

### Step 5: Verify Inventory Endpoint

Ensure GLPI's inventory endpoint is accessible:

```bash
# Test that the endpoint responds
curl -X POST http://localhost:9090/front/inventory.php \
  -H "Content-Type: application/json" \
  -d '{"action":"inventory","deviceid":"test"}'
```

Expected response: HTTP 200 or 4xx (not 404)

If you get 404, check:
- GLPI version supports native inventory (10.0+)
- Inventory plugin is enabled
- URL is correct

### Step 6: Enable GLPI Debug Mode

For deeper investigation, enable GLPI debugging:

Edit `/var/www/html/glpi/config/config_db.php`:

```php
$CFG_GLPI['debug_mode'] = true;
```

Then check GLPI logs:
- **files/_log/php-errors.log** - PHP errors
- **files/_log/sql-errors.log** - Database errors
- **files/_log/inventory.log** - Inventory processing

Look for errors related to inventory processing.

### Step 7: Check Entity & Profile Permissions

Make sure your GLPI user has permissions:

**Navigate to:** Administration → Profiles → [Your Profile]

Check these permissions:
- **Assets → Computers:** Read + Write
- **Administration → Rules:** Read
- **Tools → Inventory:** Read + Write
- **Entities:** Access to the entity where devices should appear

Also verify:
- You're viewing the correct entity (top-right entity selector)
- The rule assigns devices to an entity you can access

### Step 8: Common GLPI Configuration Issues

#### Enable Inventory Plugin (GLPI 10.0+)

**Navigate to:** Setup → Plugins

Find "Native Inventory" or similar - ensure it's:
- ✓ Installed
- ✓ Activated

#### Check API Access

**Navigate to:** Setup → General → API

Verify:
- ✓ Enable REST API
- ✓ Enable login with credentials (if using OAuth)
- URL filter: blank or includes your scanner's IP

### Step 9: Sample Working Inventory JSON

Here's what a valid GLPI inventory looks like:

```json
{
  "action": "inventory",
  "deviceid": "AA:BB:CC:DD:EE:FF",
  "itemtype": "Computer",
  "versionclient": "goscanner-v1.0",
  "content": {
    "hardware": {
      "name": "workstation-01",
      "uuid": "12345678",
      "description": "Discovered by goscanner"
    },
    "networks": [
      {
        "description": "Primary Network Interface",
        "ipaddress": "192.168.1.100",
        "macaddr": "AA:BB:CC:DD:EE:FF",
        "status": "Up",
        "type": "ethernet"
      }
    ]
  }
}
```

### Step 10: Manual Import Test

To verify GLPI is working, manually import a test device:

**Navigate to:** Assets → Computers → Add

Create a computer manually. If this works, the issue is with inventory processing, not permissions.

### Step 11: Database Check (Advanced)

If all else fails, check if data reached the database:

```sql
-- Connect to GLPI database
SELECT * FROM glpi_agentmodules WHERE name LIKE '%inventory%';
SELECT * FROM glpi_unmanageds ORDER BY date_mod DESC LIMIT 10;
SELECT * FROM glpi_computers ORDER BY date_mod DESC LIMIT 10;
```

Look for recent entries matching your scan time.

## Quick Checklist

- [ ] Scanner shows "pushing X assets" with no errors
- [ ] GLPI inventory is enabled (Setup → Plugins)
- [ ] Import rule exists and is **active**
- [ ] Import rule has **Computer import** action
- [ ] Import rule is **at top of list**
- [ ] Viewing correct entity (top-right dropdown)
- [ ] User has Computer write permissions
- [ ] Checked Administration → Inventory for refused items
- [ ] Checked Assets → Unmanaged devices
- [ ] Debug mode shows GLPI returning 200 OK

## Still Not Working?

If you've tried everything:

1. **Enable debug output in goscanner** (see Step 1)
2. **Copy the JSON output**
3. **Check GLPI logs** for the exact error
4. **Manually test** the inventory.php endpoint with curl
5. **Verify GLPI version** is 10.0+ (native inventory required)

## Known Issues

### Issue: "No rule matched"
**Solution:** Check rule criteria - try removing all criteria to accept everything

### Issue: Items appear in "Unmanaged" instead of "Computers"
**Solution:** Rule's "Item to link" action is missing or wrong

### Issue: HTTP 404 on /front/inventory.php
**Solution:** GLPI version < 10.0 doesn't have native inventory - upgrade GLPI

### Issue: HTTP 401/403 even with valid OAuth
**Solution:** Inventory endpoint might not require auth - remove auth headers for that specific endpoint

### Issue: Duplicates created on every scan
**Solution:** deviceid needs to be consistent (use MAC address, not IP)

## Getting Help

Include this info when asking for help:

1. GLPI version (`glpi-console glpi:system:status`)
2. Scanner output with debug enabled
3. JSON being sent (from debug output)
4. GLPI response (from debug output)
5. GLPI logs (Administration → Logs, filter by Inventory)
6. Screenshot of inventory rule configuration
