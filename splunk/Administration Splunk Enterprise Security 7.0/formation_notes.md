# Intro
- class : Administering Splunk Enterprise Security 7.0
- date : September 07,08,09 2022
- additional notes of course material : "Administering Splunk Enterprise Security 7.0.pdf" (non disclosable material)

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
slides 79+
- data protection dashboard : 
- add tab to investigation, not durable for future investigations
- default : ess_analyst only see their investigations
- create workbecnh panel for all investigation

# Module 5 : Installation
slides 98+
one TA <=> one data type input
SA <=> supporting addon : Splunk native and additionnal fonctionnalities
DA <=> domain addon : views, UI ; one domain - one DA

Splunk ES (enterpise security) = DA-ESS-* + SA-* + Splunk_SA_CIM + Splunk_ML_Toolkit + SplunkE...S...Suite

need to download from splunkbase TA's for inputs type (win, *-nix, etc.)

Indexes :
1. create Splunk_TA_ForIndexers on SHs
2. install it on indexers **and HFs**
Splunk_TA_ForIndexers : contains props.conf and transforms.conf and indexes.conf and more

install ES-single instance checklist : slide 105
tips :
- deploy Splunk_TA_ForIndexers as disabled, then enable it
- web.conf : increase max_upload_size to 1024
- disable unused/old ES addon

install ES-clustered SHs checklist : slide 116

## Splunk_TA_ForIndexers
Distributed Configuration Management + **auto create Splunk_TA_ForIndexers** : slide 118
**recommandation** to create and push only once Splunk_TA_ForIndexers:
- create 2 different apps : one for default index (ES indexes), one for inputs indexes (linux, aws, etc.)
  - one does only in
  - HF doesnt need index def, but need time properties
  - download one with 1st option only (Include index time properties)
  - download one with 2nd option only (Include index definitions), then rename it to a different spl file  
- objective :
  - create and push only once Splunk_TA_ForIndexers

## Splunk_TA_AROnPrem
**recommandation** :
- install one HF with this app per site/region/DMZ/etc.
- objective : allow to run adaptive response from HF to increase success rate of adaptive response (example : ping from same subnet is best than pinging from cloud Splunk instance)

**warning** success status of adaptive response <=> script run successfully **!= ping succeeded**

## Data integrity control
slides 120+
- integrity control : apply hash on indexed data
- hash can be checked : ./splunk check-integrity -index <indexname>
- **recommandation** : run it as scripted input once per day + setup alert on results**

## Stream addon
slides 122+
when enabled : make splunk instance a virtual sniffer (capture network data, ~= wireshark : doesn't get full packet, only headers + key fields as configured in splunk stream app)
- tip : turn on stream app for only X hours on Y hosts when suspicious activities detected on suspicious hosts
- compatible with SplunkCloud, no need for HF, only need connection to SplunkCloud with stream app installed

# Module 6 : initial configuration
slides 125+
## ES lookups
slides 128+
examples :
- cim_cloud_domain_lookup <=> mail domain inclusion/exclusion list
- intersting_ports_lookup
-> lot of correlations searches rely on theses lookups
-> don't change column names

## configure domain analysis
slides 130+
- every time someone access a new domain, compare it with domain analysis and add it to a report.
**recommandation** : limit domain queries to limit volume in domain report

## UBA (user behavior analytics)
slide 134

## SOAR
slide 135
Splunk app for SOAR, enable adaptive responde action to
- send ES search results to SOAR
- run playbook in SOAR

## Various tools/settings
### Incident review in kvstore collection
slide 136
- kvstore fastly increase in size
- cleanup maintenance : slide 137, option to do it in a periodically report

### untriaged incident alert
slide 138
notable event that stayed new during more than 48h

### ES config health audit
slide 139

### ES app customization
slides 140+
tip : \`get_delta macro\` : slide 147