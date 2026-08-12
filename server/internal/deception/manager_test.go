package deception

import (
	"testing"
)

func TestCreateAndTriggerToken(t *testing.T) {
	mgr := NewManager(nil)

	token, err := mgr.CreateToken(TokenCanaryFile, "test canary", "test file", "/tmp/canary.txt", "agent-1")
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}
	if token.ID == "" {
		t.Error("expected non-empty token ID")
	}
	if token.Token == "" {
		t.Error("expected non-empty token value")
	}
	if token.Triggered {
		t.Error("token should not be triggered initially")
	}

	alert, err := mgr.Trigger(token.ID, "192.168.1.100", "notepad.exe", 1234, "agent-1")
	if err != nil {
		t.Fatalf("Trigger failed: %v", err)
	}
	if alert.Severity != 95 {
		t.Errorf("expected severity 95, got %d", alert.Severity)
	}

	updated, ok := mgr.GetToken(token.ID)
	if !ok {
		t.Fatal("token not found after trigger")
	}
	if !updated.Triggered {
		t.Error("token should be triggered")
	}
	if updated.TriggerCount != 1 {
		t.Errorf("expected trigger count 1, got %d", updated.TriggerCount)
	}
}

func TestCheckToken(t *testing.T) {
	mgr := NewManager(nil)
	token, _ := mgr.CreateToken(TokenHoneyToken, "fake api key", "", "", "")

	found, ok := mgr.CheckToken(token.Token)
	if !ok {
		t.Error("token should be found by value")
	}
	if found.ID != token.ID {
		t.Error("wrong token returned")
	}

	_, notOk := mgr.CheckToken("definitely-not-a-real-token-xyz")
	if notOk {
		t.Error("non-existent token should not be found")
	}
}

func TestDeleteToken(t *testing.T) {
	mgr := NewManager(nil)
	token, _ := mgr.CreateToken(TokenCanaryFile, "to delete", "", "", "")

	if !mgr.DeleteToken(token.ID) {
		t.Error("delete should succeed")
	}
	if mgr.DeleteToken(token.ID) {
		t.Error("second delete should fail")
	}
	_, ok := mgr.GetToken(token.ID)
	if ok {
		t.Error("token should not exist after delete")
	}
}

func TestGenerateToken(t *testing.T) {
	for _, tt := range []TokenType{TokenCanaryFile, TokenHoneyCredential, TokenHoneyToken, TokenHoneyEmail} {
		val, err := generateToken(tt)
		if err != nil {
			t.Errorf("generateToken(%s) failed: %v", tt, err)
		}
		if len(val) < 10 {
			t.Errorf("token too short: %s", val)
		}
	}
}
