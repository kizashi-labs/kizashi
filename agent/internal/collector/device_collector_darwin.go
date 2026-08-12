//go:build darwin

package collector

import (
	"encoding/json"
	"os/exec"
	"strings"
)

// listDevices enumerates connected USB devices on macOS via
// `system_profiler -json SPUSBDataType` (no CGo, consistent with the other
// Darwin collectors that shell out to ps/lsof/tcpdump/log). Previously this
// returned an empty slice, so USB insertion — removable-media exfiltration and
// BadUSB (T1200 Hardware Additions) — was completely invisible on macOS.
//
// The DeviceCollector diffs successive scans, so steady-state built-in devices
// (keyboard/trackpad) seed the known set and only newly-connected devices emit
// events.
func listDevices() ([]DeviceInfo, error) {
	out, err := exec.Command("system_profiler", "-json", "SPUSBDataType").Output()
	if err != nil {
		// system_profiler missing or errored — degrade gracefully (no events).
		return nil, nil
	}
	return parseSystemProfilerUSB(out), nil
}

// parseSystemProfilerUSB walks the SPUSBDataType tree and returns every node
// that carries a vendor/product id (i.e. a real device, not a bus/hub).
func parseSystemProfilerUSB(jsonOut []byte) []DeviceInfo {
	var root struct {
		Items []spusbNode `json:"SPUSBDataType"`
	}
	if err := json.Unmarshal(jsonOut, &root); err != nil {
		return nil
	}

	var devices []DeviceInfo
	var walk func(nodes []spusbNode)
	walk = func(nodes []spusbNode) {
		for _, n := range nodes {
			if n.VendorID != "" || n.ProductID != "" {
				vid := extractHexID(n.VendorID)
				pid := extractHexID(n.ProductID)
				name := strings.TrimSpace(n.Name)
				if name == "" {
					name = vid + ":" + pid
				}
				// Prefer the serial number as the stable identity; fall back to
				// vendor:product:name so re-insertion of the same model is stable.
				id := strings.TrimSpace(n.SerialNum)
				if id == "" {
					id = vid + ":" + pid + ":" + name
				}
				devices = append(devices, DeviceInfo{
					ID:        id,
					Name:      name,
					Type:      "usb",
					VendorID:  vid,
					ProductID: pid,
				})
			}
			if len(n.Items) > 0 {
				walk(n.Items)
			}
		}
	}
	walk(root.Items)
	return devices
}

// spusbNode is one node of the system_profiler SPUSBDataType tree. USB buses
// contain hubs which contain devices, all under the "_items" key.
type spusbNode struct {
	Name      string      `json:"_name"`
	VendorID  string      `json:"vendor_id"`
	ProductID string      `json:"product_id"`
	SerialNum string      `json:"serial_num"`
	Items     []spusbNode `json:"_items"`
}

// extractHexID pulls the hex id out of a system_profiler vendor/product string
// such as "0x05ac  (Apple Inc.)" → "05ac". Returns "" for an empty input.
func extractHexID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	tok := strings.Fields(s)[0]
	tok = strings.TrimPrefix(tok, "0x")
	tok = strings.TrimPrefix(tok, "0X")
	return strings.ToLower(tok)
}
