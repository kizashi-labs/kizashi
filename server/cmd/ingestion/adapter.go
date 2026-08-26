package main

import (
	"context"
	"time"

	"github.com/edr-platform/server/internal/ingestion"
	"github.com/edr-platform/server/internal/store"
)

type agentStoreAdapter struct {
	*store.AgentStore
}

func (a *agentStoreAdapter) GetAgentByID(ctx context.Context, id string) (*ingestion.AgentRecord, error) {
	row, err := a.AgentStore.GetAgentByID(ctx, id)
	if err != nil {
		return nil, err
	}
	rec := &ingestion.AgentRecord{
		ID:            row.ID,
		Hostname:      row.Hostname,
		OSType:        row.OSType,
		OSVersion:     row.OSVersion,
		AgentVersion:  row.AgentVersion,
		IPAddresses:   row.IPAddresses,
		Status:        row.Status,
		ConfigVersion: row.ConfigVersion,
	}
	if row.LastSeen != nil {
		rec.LastSeen = *row.LastSeen
	}
	if row.TLSThumbprint != nil {
		rec.TLSThumbprint = *row.TLSThumbprint
	}
	return rec, nil
}

func (a *agentStoreAdapter) UpsertAgent(ctx context.Context, agent *ingestion.AgentRecord) error {
	lastSeen := agent.LastSeen
	thumbprint := agent.TLSThumbprint
	row := &store.AgentRow{
		ID:            agent.ID,
		Hostname:      agent.Hostname,
		OSType:        agent.OSType,
		OSVersion:     agent.OSVersion,
		AgentVersion:  agent.AgentVersion,
		IPAddresses:   agent.IPAddresses,
		Status:        agent.Status,
		LastSeen:      &lastSeen,
		TLSThumbprint: &thumbprint,
		ConfigVersion: agent.ConfigVersion,
		EnrolledAt:    time.Now(),
	}
	return a.AgentStore.UpsertAgent(ctx, row)
}
