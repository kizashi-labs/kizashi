//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"strings"
)

// listDevices enumerates USB devices by reading /sys/bus/usb/devices/.
// For each device directory that represents a real USB device (has idVendor),
// it reads idVendor, idProduct, manufacturer, and product files.
// Returns an empty slice (no error) when /sys/bus/usb/devices/ does not exist
// so the collector degrades gracefully on non-Linux systems or in containers.
func listDevices() ([]DeviceInfo, error) {
	const sysUSB = "/sys/bus/usb/devices"

	entries, err := os.ReadDir(sysUSB)
	if err != nil {
		// /sys is not mounted (e.g. container without sysfs) — return empty gracefully.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var devices []DeviceInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		devPath := filepath.Join(sysUSB, entry.Name())

		// Only process entries that have idVendor — these represent USB devices.
		vendorID := readSysFile(devPath, "idVendor")
		if vendorID == "" {
			continue
		}

		productID := readSysFile(devPath, "idProduct")
		manufacturer := readSysFile(devPath, "manufacturer")
		product := readSysFile(devPath, "product")

		// Build a friendly display name: prefer "manufacturer product", fall back to IDs.
		name := strings.TrimSpace(manufacturer + " " + product)
		if strings.TrimSpace(name) == "" {
			name = vendorID + ":" + productID
		}

		// Classify device type heuristically from the bDeviceClass file.
		// Class 0x09 = Hub (skip), 0x08 = Mass Storage, 0x03 = HID (input), 0x02 = CDC (network).
		devClass := readSysFile(devPath, "bDeviceClass")
		devType := classifyUSBDevice(devClass)
		if devType == "hub" {
			// Suppress internal USB hubs — not interesting for security monitoring.
			continue
		}

		devices = append(devices, DeviceInfo{
			ID:        entry.Name(),
			Name:      name,
			Type:      devType,
			VendorID:  vendorID,
			ProductID: productID,
		})
	}

	return devices, nil
}

// readSysFile reads a single-line text file from a sysfs device directory.
// Returns an empty string on any error (permission denied, file not found, etc.).
func readSysFile(devPath, filename string) string {
	data, err := os.ReadFile(filepath.Join(devPath, filename))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// classifyUSBDevice maps a USB bDeviceClass hex string to a human-readable type.
func classifyUSBDevice(bClass string) string {
	switch strings.ToLower(strings.TrimSpace(bClass)) {
	case "08":
		return "storage"
	case "03":
		return "input"
	case "02", "0a", "e0":
		return "network"
	case "09":
		return "hub"
	default:
		return "usb"
	}
}
