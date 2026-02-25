from __future__ import annotations

import os
from typing import List, Literal, Optional

import asyncpg
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]


class ThreatIn(BaseModel):
  id: Optional[str] = None
  alert_id: Optional[str] = None
  type: str
  module: Optional[str] = None
  risk_level: Severity
  confidence: int = Field(ge=0, le=100)
  explanation: Optional[str] = None
  source_ip: Optional[str] = None
  status: Optional[str] = None


class AssistantAnalysis(BaseModel):
  explanation: str
  severity_level: Severity
  immediate_actions: List[str]
  prevention_tips: List[str]
  technical_mitigation: List[str]
  estimated_risk: int = Field(ge=0, le=100)


class UserProgressOut(BaseModel):
  xp: int
  level: int
  badges: List[str]
  total_actions: int


class UserProgressEventIn(BaseModel):
  event: Literal[
    "read_prevention_tips",
    "completed_immediate_actions",
    "reduced_threat",
    "updated_settings",
  ]
  threat_id: Optional[str] = None


EVENT_XP = {
  "read_prevention_tips": 25,
  "completed_immediate_actions": 60,
  "reduced_threat": 80,
  "updated_settings": 40,
}

LEVEL_THRESHOLDS = {
  1: 0,
  2: 300,
  3: 800,
  4: 1600,
  5: 2800,
}


def compute_level(xp: int) -> int:
  current = 1
  for lvl, threshold in sorted(LEVEL_THRESHOLDS.items(), key=lambda x: x[0]):
    if xp >= threshold:
      current = lvl
  return current


def build_assistant_response(threat: ThreatIn) -> AssistantAnalysis:
  base_risk = max(10, min(threat.confidence, 99))
  if threat.risk_level == "critical":
    boost = 10
  elif threat.risk_level == "high":
    boost = 5
  elif threat.risk_level == "medium":
    boost = 0
  else:
    boost = -5
  estimated = max(0, min(base_risk + boost, 99))

  t = threat.type.lower()

  if "ddos" in t:
    return AssistantAnalysis(
      explanation=(
        "A DDoS (Distributed Denial of Service) attack attempts to overwhelm your "
        "public-facing services with large volumes of traffic so legitimate users "
        "cannot reach them."
      ),
      severity_level=threat.risk_level,
      immediate_actions=[
        "Validate current impact on critical services and notify the on-call responder.",
        "Tighten or enable rate limiting and connection caps at your edge or load balancer.",
        "Activate any DDoS protection or scrubbing profiles offered by your provider.",
      ],
      prevention_tips=[
        "Keep internet-facing services behind a WAF or CDN that supports DDoS protection.",
        "Define traffic baselines and alerts for abnormal spikes per region and per IP.",
        "Regularly review exposed services and remove or restrict anything non-essential.",
      ],
      technical_mitigation=[
        "Introduce network ACLs or firewall rules to block obviously abusive IP ranges.",
        "Tune SYN and connection limits and apply per-source quotas on critical endpoints.",
        "Use autoscaling with safeguards so surges do not collapse core infrastructure.",
      ],
      estimated_risk=estimated,
    )

  if "brute" in t:
    return AssistantAnalysis(
      explanation=(
        "A brute force or credential-stuffing attack repeatedly tries passwords "
        "to break into accounts, often using leaked credential lists."
      ),
      severity_level=threat.risk_level,
      immediate_actions=[
        "Temporarily block the attacking IP or IP range at your firewall or WAF.",
        "Enforce multi-factor authentication on the targeted accounts.",
        "Audit recent logins for suspicious successes around the time of this alert.",
      ],
      prevention_tips=[
        "Require strong passwords and mandatory MFA, especially for privileged accounts.",
        "Configure lockout or step-up verification after several failed attempts.",
        "Monitor for sign-ins from impossible travel locations or unusual devices.",
      ],
      technical_mitigation=[
        "Apply IP- and user-based rate limits on authentication endpoints.",
        "Integrate breached-password screening before accepting new passwords.",
        "Centralize authentication logs and correlate for distributed password-spraying.",
      ],
      estimated_risk=estimated,
    )

  if "port scan" in t:
    return AssistantAnalysis(
      explanation=(
        "A port scan systematically checks which ports are open on your systems, "
        "similar to an intruder testing which doors and windows are unlocked."
      ),
      severity_level=threat.risk_level,
      immediate_actions=[
        "Block or throttle the source IP if the scan is aggressive or repeated.",
        "Confirm that only required services and ports are exposed to the internet.",
        "Investigate whether any unexpected services are listening externally.",
      ],
      prevention_tips=[
        "Maintain a strict allowlist of exposed ports and services by asset.",
        "Place critical systems behind additional firewalls, VPNs, or zero-trust access.",
        "Run regular internal vulnerability and port scans to discover misconfigurations.",
      ],
      technical_mitigation=[
        "Enable IDS/IPS rules that detect and dampen scan behavior.",
        "Use port-knocking or single-port gateways for sensitive management services.",
        "Ensure that administrative interfaces are never directly exposed to the internet.",
      ],
      estimated_risk=estimated,
    )

  if "botnet" in t:
    return AssistantAnalysis(
      explanation=(
        "Botnet traffic indicates many compromised machines being remotely controlled "
        "to attack or probe your infrastructure in a coordinated way."
      ),
      severity_level=threat.risk_level,
      immediate_actions=[
        "Check for signs of compromise on internal hosts that might be participating.",
        "Block known command-and-control domains and IPs used by the botnet.",
        "Increase monitoring of targeted services for lateral movement or data theft.",
      ],
      prevention_tips=[
        "Keep endpoint protection, OS patches, and browsers up to date on all devices.",
        "Filter malicious email attachments and URLs to prevent initial compromise.",
        "Educate users to recognize phishing and suspicious downloads.",
      ],
      technical_mitigation=[
        "Apply outbound filtering and DNS security to restrict connections to known-good destinations.",
        "Use threat intelligence feeds to automatically block emerging botnet infrastructure.",
        "Continuously hunt for persistence mechanisms and unusual outbound beacons on endpoints.",
      ],
      estimated_risk=estimated,
    )

  if "anomaly" in t:
    return AssistantAnalysis(
      explanation=(
        "An anomaly means behavior was detected that significantly deviates from your "
        "normal baseline and may represent a new or stealthy attack."
      ),
      severity_level=threat.risk_level,
      immediate_actions=[
        "Correlate this anomaly with recent changes, deployments, or access grants.",
        "Inspect logs for strange access patterns, data transfers, or privilege changes.",
        "If compromise is suspected, isolate impacted systems and begin an incident investigation.",
      ],
      prevention_tips=[
        "Refine baselines and thresholds so anomaly alerts stay meaningful.",
        "Ensure critical assets log to a central SIEM with adequate retention.",
        "Practice incident response around low-and-slow or novel attack patterns.",
      ],
      technical_mitigation=[
        "Augment SIEM detection rules based on this new behavior.",
        "Increase telemetry (process, DNS, network flow) on suspicious assets.",
        "Adopt just-in-time and least-privilege access to minimize blast radius.",
      ],
      estimated_risk=estimated,
    )

  return AssistantAnalysis(
    explanation=(
      f"The system detected a {threat.type} event which may indicate malicious activity "
      "and should be reviewed in context."
    ),
    severity_level=threat.risk_level,
    immediate_actions=[
      "Review the full alert details and affected assets in the dashboard.",
      "Validate whether this behavior is expected for the impacted systems.",
      "If uncertain, treat as suspicious and restrict access until validated.",
    ],
    prevention_tips=[
      "Document expected behaviors for critical systems so anomalies stand out.",
      "Regularly review account permissions and apply least privilege.",
      "Maintain an up-to-date asset inventory with clear ownership.",
    ],
    technical_mitigation=[
      "Tune detection rules to better classify similar events in the future.",
      "Correlate with endpoint, identity, and network telemetry to improve signal.",
      "If this pattern persists, codify it as a dedicated detection rule.",
    ],
    estimated_risk=estimated,
  )


app = FastAPI(title="Sentinel Spark Shield Assistant API")

app.add_middleware(
  CORSMiddleware,
  allow_origins=["*"],
  allow_credentials=True,
  allow_methods=["*"],
  allow_headers=["*"],
)


async def get_pool() -> asyncpg.Pool:
  database_url = os.getenv("DATABASE_URL")
  if not database_url:
    raise RuntimeError("DATABASE_URL is not configured")
  return await asyncpg.create_pool(database_url)


async def get_current_user_id(request: Request) -> str:
  user_id = request.headers.get("X-User-Id")
  if not user_id:
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Missing X-User-Id header for authenticated requests",
    )
  return user_id


@app.post("/api/assistant/analyze-threat", response_model=AssistantAnalysis)
async def analyze_threat(threat: ThreatIn, user_id: str = Depends(get_current_user_id)) -> AssistantAnalysis:
  _ = user_id
  return build_assistant_response(threat)


@app.get("/api/threats/live", response_model=Optional[ThreatIn])
async def latest_threat(pool: asyncpg.Pool = Depends(get_pool)) -> Optional[ThreatIn]:
  async with pool.acquire() as conn:
    row = await conn.fetchrow(
      """
      select id, alert_id, type, module, risk_level, confidence, explanation, source_ip, status
      from public.threat_events
      order by created_at desc
      limit 1
      """
    )
  if not row:
    return None
  return ThreatIn(
    id=str(row["id"]),
    alert_id=row["alert_id"],
    type=row["type"],
    module=row["module"],
    risk_level=row["risk_level"],
    confidence=row["confidence"],
    explanation=row["explanation"],
    source_ip=row["source_ip"],
    status=row["status"],
  )


@app.get("/api/user/progress", response_model=UserProgressOut)
async def get_user_progress(
  user_id: str = Depends(get_current_user_id),
  pool: asyncpg.Pool = Depends(get_pool),
) -> UserProgressOut:
  async with pool.acquire() as conn:
    row = await conn.fetchrow(
      """
      select xp, level, badges, total_actions
      from public.user_progress
      where user_id = $1
      """,
      user_id,
    )
    if not row:
      await conn.execute(
        """
        insert into public.user_progress (user_id, xp, level, badges, total_actions)
        values ($1, 0, 1, '{}'::text[], 0)
        """,
        user_id,
      )
      return UserProgressOut(xp=0, level=1, badges=[], total_actions=0)

  return UserProgressOut(
    xp=row["xp"],
    level=row["level"],
    badges=row["badges"] or [],
    total_actions=row["total_actions"],
  )


@app.post("/api/user/progress", response_model=UserProgressOut)
async def update_user_progress(
  payload: UserProgressEventIn,
  user_id: str = Depends(get_current_user_id),
  pool: asyncpg.Pool = Depends(get_pool),
) -> UserProgressOut:
  gained = EVENT_XP.get(payload.event, 0)
  async with pool.acquire() as conn:
    row = await conn.fetchrow(
      """
      insert into public.user_progress (user_id, xp, level, badges, total_actions)
      values ($1, 0, 1, '{}'::text[], 0)
      on conflict (user_id) do update set
        xp = public.user_progress.xp,
        level = public.user_progress.level
      returning xp, level, badges, total_actions
      """,
      user_id,
    )
    current_xp = int(row["xp"]) + gained
    new_level = compute_level(current_xp)
    total_actions = int(row["total_actions"]) + 1
    badges = list(row["badges"] or [])

    if total_actions >= 1 and "First Response" not in badges:
      badges.append("First Response")
    if total_actions >= 10 and "Playbook Follower" not in badges:
      badges.append("Playbook Follower")
    if total_actions >= 25 and "Incident Wrangler" not in badges:
      badges.append("Incident Wrangler")
    if new_level >= 3 and "Threat Hunter" not in badges:
      badges.append("Threat Hunter")
    if new_level >= 5 and "SOC Commander" not in badges:
      badges.append("SOC Commander")

    await conn.execute(
      """
      update public.user_progress
      set xp = $2,
          level = $3,
          badges = $4,
          total_actions = $5,
          updated_at = now()
      where user_id = $1
      """,
      user_id,
      current_xp,
      new_level,
      badges,
      total_actions,
    )

  return UserProgressOut(xp=current_xp, level=new_level, badges=badges, total_actions=total_actions)


