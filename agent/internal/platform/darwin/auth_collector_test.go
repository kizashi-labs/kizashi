//go:build darwin

package darwin

import "testing"

func TestParseDarwinAuthLine(t *testing.T) {
	cases := []struct {
		name       string
		line       string
		wantOK     bool
		wantUser   string
		wantAction string
		wantOK2    bool // wantSuccess
		wantIP     string
	}{
		{
			name:       "ssh accepted",
			line:       `2026-07-20 12:00:00.000000+0900 Mac sshd[501]: Accepted publickey for alice from 10.0.0.9 port 51234 ssh2`,
			wantOK:     true,
			wantUser:   "alice",
			wantAction: "login",
			wantOK2:    true,
			wantIP:     "10.0.0.9",
		},
		{
			name:       "ssh failed password",
			line:       `2026-07-20 12:00:01.000000+0900 Mac sshd[502]: Failed password for bob from 1.2.3.4 port 22 ssh2`,
			wantOK:     true,
			wantUser:   "bob",
			wantAction: "failed",
			wantOK2:    false,
			wantIP:     "1.2.3.4",
		},
		{
			name:       "ssh failed invalid user",
			line:       `2026-07-20 12:00:02.000000+0900 Mac sshd[503]: Failed password for invalid user root from 5.6.7.8 port 22 ssh2`,
			wantOK:     true,
			wantUser:   "root",
			wantAction: "failed",
			wantOK2:    false,
			wantIP:     "5.6.7.8",
		},
		{
			name:       "sudo command (privilege)",
			line:       `2026-07-20 12:00:03.000000+0900 Mac sudo[600]: alice : TTY=ttys000 ; PWD=/Users/alice ; USER=root ; COMMAND=/bin/ls`,
			wantOK:     true,
			wantUser:   "alice",
			wantAction: "privilege",
			wantOK2:    true,
		},
		{
			name:       "sudo incorrect password (failed)",
			line:       `2026-07-20 12:00:04.000000+0900 Mac sudo[601]: mallory : 3 incorrect password attempts ; TTY=ttys001 ; PWD=/ ; USER=root`,
			wantOK:     true,
			wantUser:   "mallory",
			wantAction: "failed",
			wantOK2:    false,
		},
		{
			name:   "unrelated line",
			line:   `2026-07-20 12:00:05.000000+0900 Mac loginwindow[123]: some unrelated message`,
			wantOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evt, ok := parseDarwinAuthLine(c.line)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if evt.Username != c.wantUser {
				t.Errorf("user = %q, want %q", evt.Username, c.wantUser)
			}
			if evt.Action != c.wantAction {
				t.Errorf("action = %q, want %q", evt.Action, c.wantAction)
			}
			if evt.Success != c.wantOK2 {
				t.Errorf("success = %v, want %v", evt.Success, c.wantOK2)
			}
			if c.wantIP != "" && evt.SourceIP != c.wantIP {
				t.Errorf("ip = %q, want %q", evt.SourceIP, c.wantIP)
			}
		})
	}
}
