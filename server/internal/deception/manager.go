package deception

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TokenType represents the type of deception token
type TokenType string

const (
	TokenCanaryFile      TokenType = "canary_file"
	TokenHoneyCredential TokenType = "honey_credential"
	TokenHoneyToken      TokenType = "honey_token" // fake API key/JWT
	TokenHoneyEmail      TokenType = "honey_email"
	TokenHoneyHost       TokenType = "honey_host" // fake hostname in DNS
	TokenHoneyUser       TokenType = "honey_user" // fake user account
)

// DeceptionToken is a placed deception artifact
type DeceptionToken struct {
	ID           string     `json:"id"`
	Type         TokenType  `json:"type"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Token        string     `json:"token"`          // the actual token value
	Path         string     `json:"path,omitempty"` // file path if canary file
	AgentID      string     `json:"agent_id,omitempty"`
	Triggered    bool       `json:"triggered"`
	TriggerCount int        `json:"trigger_count"`
	LastTrigger  *time.Time `json:"last_trigger,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	Enabled      bool       `json:"enabled"`
	Tags         []string   `json:"tags,omitempty"`
}

// TokenAlert is generated when a deception token is accessed
type TokenAlert struct {
	ID          string    `json:"id"`
	TokenID     string    `json:"token_id"`
	TokenType   TokenType `json:"token_type"`
	TokenName   string    `json:"token_name"`
	AgentID     string    `json:"agent_id,omitempty"`
	SourceIP    string    `json:"source_ip,omitempty"`
	ProcessID   int       `json:"process_id,omitempty"`
	ProcessName string    `json:"process_name,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    int       `json:"severity"` // always high: 90-95
}

// Manager manages deception tokens
type Manager struct {
	mu     sync.RWMutex
	tokens map[string]*DeceptionToken
	alerts []TokenAlert
	pool   *pgxpool.Pool
}

// NewManager creates a new deception Manager
func NewManager(pool *pgxpool.Pool) *Manager {
	return &Manager{
		tokens: make(map[string]*DeceptionToken),
		pool:   pool,
	}
}

// CreateToken creates a new deception token
func (m *Manager) CreateToken(tokenType TokenType, name, description, path, agentID string) (*DeceptionToken, error) {
	id, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("generate id: %w", err)
	}
	tokenValue, err := generateToken(tokenType)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	t := &DeceptionToken{
		ID:           id,
		Type:         tokenType,
		Name:         name,
		Description:  description,
		Token:        tokenValue,
		Path:         path,
		AgentID:      agentID,
		Triggered:    false,
		TriggerCount: 0,
		CreatedAt:    time.Now(),
		Enabled:      true,
	}

	m.mu.Lock()
	m.tokens[id] = t
	m.mu.Unlock()

	return t, nil
}

// Trigger records a token access and generates an alert
func (m *Manager) Trigger(tokenID, sourceIP, processName string, processID int, agentID string) (*TokenAlert, error) {
	m.mu.Lock()
	t, ok := m.tokens[tokenID]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("token %s not found", tokenID)
	}
	t.Triggered = true
	t.TriggerCount++
	now := time.Now()
	t.LastTrigger = &now
	m.mu.Unlock()

	alertID, _ := generateID()
	alert := TokenAlert{
		ID:          alertID,
		TokenID:     tokenID,
		TokenType:   t.Type,
		TokenName:   t.Name,
		AgentID:     agentID,
		SourceIP:    sourceIP,
		ProcessID:   processID,
		ProcessName: processName,
		Timestamp:   time.Now(),
		Severity:    95, // Deception token triggers are always high severity
	}

	m.mu.Lock()
	m.alerts = append(m.alerts, alert)
	m.mu.Unlock()

	return &alert, nil
}

// CheckToken checks if a given token value matches any deployed token (for detection)
func (m *Manager) CheckToken(tokenValue string) (*DeceptionToken, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.tokens {
		if t.Enabled && t.Token == tokenValue {
			return t, true
		}
	}
	return nil, false
}

// GetTokens returns all tokens
func (m *Manager) GetTokens() []*DeceptionToken {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tokens := make([]*DeceptionToken, 0, len(m.tokens))
	for _, t := range m.tokens {
		tokens = append(tokens, t)
	}
	return tokens
}

// GetToken returns a specific token by ID
func (m *Manager) GetToken(id string) (*DeceptionToken, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tokens[id]
	return t, ok
}

// DeleteToken removes a token
func (m *Manager) DeleteToken(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.tokens[id]
	if ok {
		delete(m.tokens, id)
	}
	return ok
}

// GetAlerts returns recent deception alerts
func (m *Manager) GetAlerts(limit int) []TokenAlert {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > len(m.alerts) {
		limit = len(m.alerts)
	}
	start := len(m.alerts) - limit
	if start < 0 {
		start = 0
	}
	result := make([]TokenAlert, len(m.alerts)-start)
	copy(result, m.alerts[start:])
	return result
}

// Stats returns deception statistics
func (m *Manager) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	triggered := 0
	for _, t := range m.tokens {
		if t.Triggered {
			triggered++
		}
	}
	return map[string]interface{}{
		"total_tokens": len(m.tokens),
		"triggered":    triggered,
		"total_alerts": len(m.alerts),
	}
}

func generateID() (string, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateToken(tokenType TokenType) (string, error) {
	b := make([]byte, 24)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	prefix := "honey"
	switch tokenType {
	case TokenHoneyCredential:
		prefix = "passwd"
	case TokenHoneyToken:
		prefix = "edr_"
	case TokenHoneyEmail:
		prefix = "canary@"
	default:
		prefix = "canary"
	}
	return prefix + hex.EncodeToString(b), nil
}
