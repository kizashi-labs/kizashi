//go:build linux

package linux

import "testing"

// TestParseAuthLine covers the auth-log line shapes the collector must recognise
// (SSH login success/failure, sudo/su privilege and failures) and confirms benign
// lines are ignored, so the brute-force detector and auth Sigma rules get clean input.
func TestParseAuthLine(t *testing.T) {
	cases := []struct {
		name       string
		line       string
		wantOK     bool
		wantUser   string
		wantAction string
		wantOK2    bool // Success
		wantIP     string
	}{
		{
			name:   "sshd accepted password",
			line:   "Jul  2 09:15:01 host sshd[1234]: Accepted password for alice from 203.0.113.5 port 55016 ssh2",
			wantOK: true, wantUser: "alice", wantAction: "login", wantOK2: true, wantIP: "203.0.113.5",
		},
		{
			name:   "sshd accepted publickey",
			line:   "Jul  2 09:15:01 host sshd[1234]: Accepted publickey for bob from 10.0.0.9 port 40000 ssh2: RSA SHA256:xxx",
			wantOK: true, wantUser: "bob", wantAction: "login", wantOK2: true, wantIP: "10.0.0.9",
		},
		{
			name:   "sshd failed password",
			line:   "Jul  2 09:16:20 host sshd[1300]: Failed password for root from 198.51.100.7 port 33002 ssh2",
			wantOK: true, wantUser: "root", wantAction: "failed", wantOK2: false, wantIP: "198.51.100.7",
		},
		{
			name:   "sshd failed invalid user",
			line:   "Jul  2 09:16:22 host sshd[1301]: Failed password for invalid user admin from 198.51.100.7 port 33010 ssh2",
			wantOK: true, wantUser: "admin", wantAction: "failed", wantOK2: false, wantIP: "198.51.100.7",
		},
		{
			name:   "sshd invalid user",
			line:   "Jul  2 09:16:22 host sshd[1301]: Invalid user oracle from 198.51.100.7 port 33012",
			wantOK: true, wantUser: "oracle", wantAction: "failed", wantOK2: false, wantIP: "198.51.100.7",
		},
		{
			name:   "sudo command (privilege)",
			line:   "Jul  2 09:17:00 host sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
			wantOK: true, wantUser: "alice", wantAction: "privilege", wantOK2: true,
		},
		{
			name:   "sudo authentication failure",
			line:   "Jul  2 09:17:30 host sudo:   eve : 1 incorrect password attempt ; TTY=pts/1 ; authentication failure",
			wantOK: true, wantUser: "eve", wantAction: "failed", wantOK2: false,
		},
		{
			name:   "su session opened (privilege)",
			line:   "Jul  2 09:18:00 host su[2000]: (to root) alice on pts/0 session opened for user root by (uid=1000)",
			wantOK: true, wantAction: "privilege", wantOK2: true,
		},
		{
			name:   "su failed",
			line:   "Jul  2 09:18:10 host su[2001]: FAILED su for root by alice",
			wantOK: true, wantUser: "root", wantAction: "failed", wantOK2: false,
		},
		{
			name:   "benign cron line ignored",
			line:   "Jul  2 09:19:00 host CRON[3000]: pam_unix(cron:session): session opened for user root(uid=0)",
			wantOK: false,
		},
		{
			name:   "unrelated line ignored",
			line:   "Jul  2 09:19:01 host systemd[1]: Started Session 42 of user ubuntu.",
			wantOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evt, ok := parseAuthLine(c.line)
			if ok != c.wantOK {
				t.Fatalf("ok=%v want %v (line=%q)", ok, c.wantOK, c.line)
			}
			if !c.wantOK {
				return
			}
			if c.wantUser != "" && evt.Username != c.wantUser {
				t.Errorf("user=%q want %q", evt.Username, c.wantUser)
			}
			if evt.Action != c.wantAction {
				t.Errorf("action=%q want %q", evt.Action, c.wantAction)
			}
			if evt.Success != c.wantOK2 {
				t.Errorf("success=%v want %v", evt.Success, c.wantOK2)
			}
			if c.wantIP != "" && evt.SourceIP != c.wantIP {
				t.Errorf("ip=%q want %q", evt.SourceIP, c.wantIP)
			}
		})
	}
}
