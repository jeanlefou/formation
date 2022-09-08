# Intro
class : Administering Splunk Enterprise Security 7.0
date : September 07,08,09 2022
additional notes of course material : "Administering Splunk Enterprise Security 7.0.pdf"

## Goals
- admin ES, not using ES
- complete all labs

# Module 1 : Introduction to ES
- slide 9 : data flow in ES 
  - 1. raw events in index
  - 2. data model
  - 3. | tstats (sullariesonly = true -> search accelerated data)
  - 4. background searches (correlations searches, trackers, threat intel DMs)
  - 5. threats and anomalies searches

-> really insist with client to invest effort to normalize data with CIM (ES=f(data model))

## Correlation search
Splunk_SA_CIM
SA : supporting addon
Splunk : app editor
CIM : app name commin information model

slide 15 : correlation searches def.

tip for correlation search "expired user activity", for user without expiration date, create lookup generator/editor search to automatically add an expiration date for user.

tip to edit correlation search without loosing the original one :
1. clone it
2. then edit the clone

## Notable event
- stored in index=notable

## Misc
- slide 22 : edit ES roles
- don't install addon builder on prod

# Module 2 : Security Monitoring
slide 26+
same info than in "Using Splunk Enterprise Security 7.0" + :
- event_id for notable events : uses server id + various id + hashes
  -> option to create short ID, click shortID in incident review dashboard on a notable event
- Notable event urgency def : slide 33-35 =f(
  - severity=f(notable event severity)
  - priority=f(assets/identity priority)
)
slide 35 urgency matrix-> beware of typo, it'll break lookup
- Notable event status value & other settings : slide 36-44
- workflow actions : slides 45-48
- create/delete Ad hoc Notable Events (for events found manually): slides 49-51
  - tip : create correlation search to detect it again
  - delete/hide notable event, uc example : honeypot server
    - action/supress notabe event ; beware of settings limitation to supress (duration, 1 src_host only, etc.)
    - suppression audit dashboard : monitor suppressions

# Module 3 : Risk-Based Alerting
## Risk score : Risk-Based Alerting
slide 58+
same info than in "Using Splunk Enterprise Security 7.0" + :
- to see actions that added risk to an object : notable event/action/rick_object
- use risk analysis dashboard!
- add risk factor (!= risk analysis) : slide 69, cf risk_factors.conf
- list of security framework (MITRE ATT&CK, Kill Chain, CIS 20, and NIST) : slide 59
- risk notable : slide 32+
- setup risk permission : slide 77

# Module 4 : Incident Investigation
slide 79+
- data protection dashboard : 
- add tab to investigation, not durable for future investigations
- default : ess_analyst only see their investigations
- create workbecnh panel for all investigation