-- Compliance framework mapping tables
CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_controls (
    id             TEXT PRIMARY KEY,
    framework_id   TEXT NOT NULL REFERENCES compliance_frameworks(id),
    control_id     TEXT NOT NULL,  -- e.g. "CC6.1", "A.9.1", "Requirement 8"
    title          TEXT NOT NULL,
    description    TEXT,
    category       TEXT,
    severity       TEXT NOT NULL DEFAULT 'medium'
);

CREATE TABLE IF NOT EXISTS compliance_evidence (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id   TEXT NOT NULL REFERENCES compliance_controls(id),
    agent_id     UUID,
    event_id     TEXT,
    alert_id     UUID,
    evidence_type TEXT NOT NULL,  -- 'log' | 'config' | 'alert' | 'event'
    summary      TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pass',  -- pass | fail | not_applicable
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- SOC2 Type II framework
INSERT INTO compliance_frameworks (id, name, version, description) VALUES
('soc2', 'SOC 2 Type II', '2017', 'Service Organization Control 2 Type II')
ON CONFLICT (id) DO NOTHING;

INSERT INTO compliance_controls (id, framework_id, control_id, title, description, category, severity) VALUES
('soc2-cc6.1', 'soc2', 'CC6.1', 'Logical and Physical Access Controls', 'The entity implements logical access security software, infrastructure, and architectures', 'Common Criteria', 'high'),
('soc2-cc6.2', 'soc2', 'CC6.2', 'Prior to Issuing Credentials', 'Prior to issuing system credentials, the entity registers and authorizes new users', 'Common Criteria', 'high'),
('soc2-cc6.3', 'soc2', 'CC6.3', 'Role-Based Access', 'The entity authorizes access to data assets based on roles and responsibilities', 'Common Criteria', 'high'),
('soc2-cc7.1', 'soc2', 'CC7.1', 'System Configurations', 'The entity uses detection and monitoring procedures', 'Common Criteria', 'medium'),
('soc2-cc7.2', 'soc2', 'CC7.2', 'Monitoring of System Components', 'The entity monitors system components', 'Common Criteria', 'medium'),
('soc2-cc7.3', 'soc2', 'CC7.3', 'Evaluation of Security Events', 'The entity evaluates security events', 'Common Criteria', 'high'),
('soc2-cc7.4', 'soc2', 'CC7.4', 'Incident Response', 'The entity responds to identified security incidents', 'Common Criteria', 'critical'),
('soc2-cc8.1', 'soc2', 'CC8.1', 'Change Management', 'The entity authorizes, designs, develops, and implements changes to infrastructure, data, software, and procedures', 'Common Criteria', 'medium')
ON CONFLICT (id) DO NOTHING;

-- ISO 27001 framework
INSERT INTO compliance_frameworks (id, name, version, description) VALUES
('iso27001', 'ISO/IEC 27001', '2022', 'Information Security Management Systems')
ON CONFLICT (id) DO NOTHING;

INSERT INTO compliance_controls (id, framework_id, control_id, title, description, category, severity) VALUES
('iso27001-a8.2', 'iso27001', 'A.8.2', 'Privileged Access Rights', 'The allocation and use of privileged access rights shall be restricted and managed', 'Access Control', 'high'),
('iso27001-a8.5', 'iso27001', 'A.8.5', 'Secure Authentication', 'Secure authentication technologies and procedures shall be implemented', 'Access Control', 'high'),
('iso27001-a8.7', 'iso27001', 'A.8.7', 'Protection Against Malware', 'Protection against malware shall be implemented', 'Asset Management', 'high'),
('iso27001-a8.15', 'iso27001', 'A.8.15', 'Logging', 'Logs that record activities, exceptions, faults and other relevant events shall be produced', 'Operations Security', 'medium'),
('iso27001-a8.16', 'iso27001', 'A.8.16', 'Monitoring Activities', 'Networks, systems and applications shall be monitored', 'Operations Security', 'high'),
('iso27001-a5.26', 'iso27001', 'A.5.26', 'Response to Information Security Incidents', 'Information security incidents shall be responded to', 'Incident Management', 'critical'),
('iso27001-a5.28', 'iso27001', 'A.5.28', 'Collection of Evidence', 'The organization shall establish and implement procedures for the identification, collection, acquisition and preservation of evidence', 'Incident Management', 'high')
ON CONFLICT (id) DO NOTHING;

-- PCI-DSS v4 framework
INSERT INTO compliance_frameworks (id, name, version, description) VALUES
('pcidss', 'PCI DSS', '4.0', 'Payment Card Industry Data Security Standard v4.0')
ON CONFLICT (id) DO NOTHING;

INSERT INTO compliance_controls (id, framework_id, control_id, title, description, category, severity) VALUES
('pcidss-r1', 'pcidss', 'Requirement 1', 'Network Security Controls', 'Install and maintain network security controls', 'Network Security', 'high'),
('pcidss-r2', 'pcidss', 'Requirement 2', 'Secure Configurations', 'Apply secure configurations to all system components', 'Secure Configuration', 'high'),
('pcidss-r5', 'pcidss', 'Requirement 5', 'Protect Against Malicious Software', 'Protect all systems and networks from malicious software', 'Malware Protection', 'high'),
('pcidss-r6', 'pcidss', 'Requirement 6', 'Develop Secure Systems', 'Develop and maintain secure systems and software', 'Secure Development', 'medium'),
('pcidss-r7', 'pcidss', 'Requirement 7', 'Restrict Access', 'Restrict access to system components by business need to know', 'Access Control', 'high'),
('pcidss-r8', 'pcidss', 'Requirement 8', 'Identify Users', 'Identify users and authenticate access to system components', 'Access Control', 'high'),
('pcidss-r10', 'pcidss', 'Requirement 10', 'Log and Monitor Access', 'Log and monitor all access to system components', 'Logging & Monitoring', 'high'),
('pcidss-r12', 'pcidss', 'Requirement 12', 'Support Information Security', 'Support information security with organizational policies', 'Security Policy', 'medium')
ON CONFLICT (id) DO NOTHING;
