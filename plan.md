
# Real-Time Threat Data Streaming

## Overview
Create database tables for alerts, logs, and honeypot events, enable realtime subscriptions on them, and update all dashboard components to consume live data instead of static mock data. A simulated threat generator (edge function) will periodically insert new threats so the dashboard feels alive.

---

## Step 1: Database Migration

Create three new tables with RLS policies and enable realtime:

**`threat_events`** - stores all detected threats/alerts
- `id` (uuid, PK)
- `alert_id` (text) - e.g. "ALT-009"
- `type` (text) - "DDoS Attack", "Phishing URL", etc.
- `module` (text) - "IDS", "Phishing", "UBA", etc.
- `risk_level` (text) - low/medium/high/critical
- `confidence` (integer)
- `explanation` (text)
- `source_ip` (text)
- `status` (text) - active/investigating/resolved/ignored
- `created_at` (timestamptz)

**`threat_stats`** - rolling stats updated by triggers
- `id` (uuid, PK)
- `total_threats` (integer)
- `blocked_attacks` (integer)
- `active_alerts` (integer)
- `risk_score` (integer)
- `updated_at` (timestamptz)

**`honeypot_events`** - honeypot captures
- `id` (uuid, PK)
- `ip_address` (text)
- `payload` (text)
- `attempt_type` (text)
- `attempts` (integer)
- `created_at` (timestamptz)

All tables get:
- RLS enabled with public SELECT policies (dashboard is read-only for viewers)
- INSERT/UPDATE restricted to authenticated users or service role
- Added to `supabase_realtime` publication

Seed initial data from the existing mock data so the dashboard works immediately.

---

## Step 2: Edge Function - Threat Simulator

Create `supabase/functions/simulate-threats/index.ts`:
- On each invocation, randomly generates a new threat event and inserts it into `threat_events`
- Updates `threat_stats` row (increment counters)
- Occasionally inserts a honeypot event
- Can be called via a frontend timer (setInterval every 8-15 seconds) to simulate live activity

---

## Step 3: Custom Hook - `useRealtimeThreats`

Create `src/hooks/useRealtimeThreats.ts`:
- Fetches initial data from `threat_events` (latest 20), `threat_stats`, and `honeypot_events`
- Subscribes to `postgres_changes` on all three tables
- On INSERT to `threat_events`: prepends new alert to list, shows toast notification
- On UPDATE to `threat_stats`: updates stats counters
- On INSERT to `honeypot_events`: prepends to honeypot list
- Returns `{ alerts, stats, honeypotEvents, isConnected }`

---

## Step 4: Update Dashboard Components

**`StatsOverview.tsx`**
- Use stats from `useRealtimeThreats` instead of mock `stats` object
- Numbers animate when they change via existing `useAnimatedCounter`

**`AlertsPanel.tsx`**
- Use live alerts from the hook instead of mock `alerts` array
- New alerts appear at top with a flash animation
- Show a "LIVE" indicator with a pulsing dot

**`AnalyticsCharts.tsx`**
- Maintain a rolling time-series array in state
- Each new threat event appends a data point to the attack frequency chart
- Pie chart updates attack type distribution from live data

**`HoneypotPage.tsx`**
- Use live honeypot events from the hook
- New entries animate in

**`DashboardPage.tsx`**
- Wrap with the realtime hook provider, pass data down to child components

---

## Step 5: Live Indicator and Toast Notifications

- Add a "LIVE" badge with pulsing green dot to the Header component
- Use `sonner` toast to show brief notifications when critical/high alerts arrive
- Add a subtle flash animation on new alert cards

---

## Technical Details

```text
+------------------+       Realtime Subscription       +-------------------+
|  Edge Function   | --INSERT--> threat_events -------> | useRealtimeThreats|
| (simulate-threats)|          honeypot_events -------> |     (hook)        |
|                  |           threat_stats ----------> |                   |
+------------------+                                    +-------------------+
                                                              |
                                              +---------------+---------------+
                                              |               |               |
                                        StatsOverview   AlertsPanel   AnalyticsCharts
```

- The simulator edge function is called from the frontend via `setInterval` (every 10-15s) after login
- Realtime channel handles all live updates -- no polling needed after initial fetch
- Mock data files remain as fallback if no DB data exists yet
- RLS allows public reads so even unauthenticated preview works for stats display
