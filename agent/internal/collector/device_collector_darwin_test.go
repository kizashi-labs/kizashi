//go:build darwin

package collector

import "testing"

// sampleSPUSB mirrors `system_profiler -json SPUSBDataType`: a USB bus (no
// vendor/product id) containing a hub, which contains a real device.
const sampleSPUSB = `{
  "SPUSBDataType": [
    {
      "_name": "USB 3.1 Bus",
      "_items": [
        {
          "_name": "USB3.0 Hub",
          "vendor_id": "0x05e3  (Genesys Logic, Inc.)",
          "product_id": "0x0610",
          "_items": [
            {
              "_name": "SanDisk Ultra USB Drive",
              "vendor_id": "0x0781  (SanDisk Corp.)",
              "product_id": "0x5591",
              "serial_num": "4C530001234567890123"
            }
          ]
        }
      ]
    }
  ]
}`

func TestParseSystemProfilerUSB(t *testing.T) {
	devices := parseSystemProfilerUSB([]byte(sampleSPUSB))

	// The bus has no id and must be skipped; the hub and the flash drive remain.
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices (hub + drive), got %d: %+v", len(devices), devices)
	}

	byName := map[string]DeviceInfo{}
	for _, d := range devices {
		byName[d.Name] = d
	}

	drive, ok := byName["SanDisk Ultra USB Drive"]
	if !ok {
		t.Fatalf("flash drive not enumerated: %+v", devices)
	}
	if drive.VendorID != "0781" || drive.ProductID != "5591" {
		t.Errorf("vendor/product not parsed: %+v", drive)
	}
	if drive.ID != "4C530001234567890123" {
		t.Errorf("serial should be the stable ID, got %q", drive.ID)
	}
	if drive.Type != "usb" {
		t.Errorf("type = %q, want usb", drive.Type)
	}

	// The hub lacks a serial, so its ID falls back to vendor:product:name.
	hub, ok := byName["USB3.0 Hub"]
	if !ok {
		t.Fatalf("hub not enumerated")
	}
	if hub.ID != "05e3:0610:USB3.0 Hub" {
		t.Errorf("hub fallback ID wrong: %q", hub.ID)
	}
}

func TestExtractHexID(t *testing.T) {
	cases := map[string]string{
		"0x05ac  (Apple Inc.)": "05ac",
		"0x0781":               "0781",
		"0X8103":               "8103",
		"":                     "",
	}
	for in, want := range cases {
		if got := extractHexID(in); got != want {
			t.Errorf("extractHexID(%q) = %q, want %q", in, got, want)
		}
	}
}
