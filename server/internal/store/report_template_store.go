package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ReportTemplateSection describes a single section within a report template.
type ReportTemplateSection struct {
	Type   string                 `json:"type"`
	Title  string                 `json:"title"`
	Config map[string]interface{} `json:"config"`
}

// ReportTemplate mirrors the report_templates table.
type ReportTemplate struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Sections    []ReportTemplateSection `json:"sections"`
	Variables   map[string]interface{}  `json:"variables"`
	Format      string                  `json:"format"`
	Enabled     bool                    `json:"enabled"`
	CreatedBy   *string                 `json:"created_by,omitempty"`
	CreatedAt   time.Time               `json:"created_at"`
	UpdatedAt   time.Time               `json:"updated_at"`
}

// ReportTemplateStore manages report template persistence.
type ReportTemplateStore struct {
	pool *pgxpool.Pool
}

// NewReportTemplateStore creates a new ReportTemplateStore backed by the given pool.
func NewReportTemplateStore(pool *pgxpool.Pool) *ReportTemplateStore {
	return &ReportTemplateStore{pool: pool}
}

// List returns all report templates ordered by creation date (newest first).
func (s *ReportTemplateStore) List(ctx context.Context) ([]*ReportTemplate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, COALESCE(description,''), sections, variables, format, enabled,
		       created_by, created_at, updated_at
		FROM report_templates
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list report templates: %w", err)
	}
	defer rows.Close()

	var templates []*ReportTemplate
	for rows.Next() {
		t, err := scanReportTemplate(rows)
		if err != nil {
			continue
		}
		templates = append(templates, t)
	}
	if templates == nil {
		templates = []*ReportTemplate{}
	}
	return templates, nil
}

// Get retrieves a single report template by ID.
func (s *ReportTemplateStore) Get(ctx context.Context, id string) (*ReportTemplate, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, COALESCE(description,''), sections, variables, format, enabled,
		       created_by, created_at, updated_at
		FROM report_templates
		WHERE id = $1
	`, id)

	t, err := scanReportTemplate(row)
	if err != nil {
		return nil, fmt.Errorf("get report template %s: %w", id, err)
	}
	return t, nil
}

// Create inserts a new report template and returns the generated ID.
func (s *ReportTemplateStore) Create(ctx context.Context, t *ReportTemplate) (string, error) {
	sectionsJSON, err := json.Marshal(t.Sections)
	if err != nil {
		return "", fmt.Errorf("marshal sections: %w", err)
	}
	variablesJSON, err := json.Marshal(t.Variables)
	if err != nil {
		return "", fmt.Errorf("marshal variables: %w", err)
	}

	var id string
	err = s.pool.QueryRow(ctx, `
		INSERT INTO report_templates (name, description, sections, variables, format, enabled, created_by)
		VALUES ($1, $2, $3::jsonb, $4::jsonb, $5, $6, $7)
		RETURNING id
	`,
		t.Name,
		t.Description,
		string(sectionsJSON),
		string(variablesJSON),
		t.Format,
		t.Enabled,
		t.CreatedBy,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create report template: %w", err)
	}
	return id, nil
}

// Update modifies an existing report template.
func (s *ReportTemplateStore) Update(ctx context.Context, id string, t *ReportTemplate) error {
	sectionsJSON, err := json.Marshal(t.Sections)
	if err != nil {
		return fmt.Errorf("marshal sections: %w", err)
	}
	variablesJSON, err := json.Marshal(t.Variables)
	if err != nil {
		return fmt.Errorf("marshal variables: %w", err)
	}

	result, err := s.pool.Exec(ctx, `
		UPDATE report_templates
		SET name        = $1,
		    description = $2,
		    sections    = $3::jsonb,
		    variables   = $4::jsonb,
		    format      = $5,
		    enabled     = $6,
		    updated_at  = NOW()
		WHERE id = $7
	`,
		t.Name,
		t.Description,
		string(sectionsJSON),
		string(variablesJSON),
		t.Format,
		t.Enabled,
		id,
	)
	if err != nil {
		return fmt.Errorf("update report template: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("report template not found: %s", id)
	}
	return nil
}

// Delete removes a report template by ID.
func (s *ReportTemplateStore) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM report_templates WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("delete report template: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("report template not found: %s", id)
	}
	return nil
}

// ─── scanner helper ─────────────────────────────────────────────────────────

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanReportTemplate(row rowScanner) (*ReportTemplate, error) {
	var t ReportTemplate
	var sectionsJSON, variablesJSON string

	if err := row.Scan(
		&t.ID,
		&t.Name,
		&t.Description,
		&sectionsJSON,
		&variablesJSON,
		&t.Format,
		&t.Enabled,
		&t.CreatedBy,
		&t.CreatedAt,
		&t.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(sectionsJSON), &t.Sections); err != nil {
		t.Sections = []ReportTemplateSection{}
	}
	if t.Sections == nil {
		t.Sections = []ReportTemplateSection{}
	}

	if err := json.Unmarshal([]byte(variablesJSON), &t.Variables); err != nil {
		t.Variables = map[string]interface{}{}
	}
	if t.Variables == nil {
		t.Variables = map[string]interface{}{}
	}

	return &t, nil
}
