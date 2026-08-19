package scheduler

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// adminRecipients returns the email addresses of every enabled administrator.
//
// This lived twice, once in each notifier, as the same statement written out in
// full — and both copies filtered on `users.active`, a column no migration
// creates. The column is is_active. Measured against a database holding exactly
// one enabled admin with an address:
//
//	billing grace notifier  -> 0 recipients, 42703
//	licence expiry notifier -> 0 recipients, 42703
//
// So neither the billing-grace warnings nor the licence-expiry warnings have
// ever reached anyone by email. Both are the kind of notice whose whole value is
// arriving before a deadline: the grace notice precedes an automatic downgrade
// to the Free plan and its agent cap, and the licence notice precedes expiry.
//
// Duplicating it was what let the two drift and what would have let one be
// repaired without the other — which is exactly what happened while this fix was
// being measured. One function now, one statement, and one test covering both
// callers.
func adminRecipients(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	rows, err := pool.Query(ctx, `
		SELECT email FROM users
		 WHERE role = 'admin'
		   AND email IS NOT NULL
		   AND email <> ''
		   AND is_active = true`)
	if err != nil {
		return nil, fmt.Errorf("scheduler: read admin recipients: %w", err)
	}
	defer rows.Close()

	var emails []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, fmt.Errorf("scheduler: scan admin recipient: %w", err)
		}
		if e != "" {
			emails = append(emails, e)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scheduler: iterate admin recipients: %w", err)
	}
	return emails, nil
}
