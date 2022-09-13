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

Note from labo instructions :
"Select Include _index time properties_ to include the props.conf and transforms.conf files in the package and _Include index definitions_ to include the indexes.conf file in the package. "

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
tip : accelerate some KIs of security posture dashboard

# Module 7 : Validating ES Data
slides 149+
- data journey from src to accelerated DM : slide 153
- tstats cmd : pull data from hpas storage
- normalization process : slide 156
- tip : CIM setup page (ES/configure/cim setup) for DM setup in ES settings, easier to use than DM settings in search app
- https://docs.splunk.com/Documentation/ES/latest/Admin/Dashboardrequirements : "The Enterprise Security dashboards rely on events that conform to the Common Information Model (CIM), and are populated from data model accelerations unless otherwise noted. "
- initial data verif : slide 161, NB : (1 sourcetype) - (1-* DM)
- troubleshoot DM acceleration : DM audit dashboard
- troubleshoot FW : FW audit dashboard (all source permanently send logs, except NetworkSwitch and few others)

# Module 8 : Custom Add-ons
slides 172+

objective : make custom data src CIM-compliant
- eval=<regex> <calculate field> <etc.>
- minimum fields to extract + advise to calculate some of them : https://docs.splunk.com/Documentation/ES/latest/Admin/Dashboardrequirements

use addon builder
**recommandation** : provide all fields that cannot be mapped into the data model with static entries like NULL N/A and so on.

# Module 9 : tunging correlation searches
slides 191+

**recommandations** :
- start ES with with only enabling a small number of correlation search, enable new ones only when the already enabled are mature (IDS/IPS/FW policies improved, correlations searches cloned and sensibility adjusted, etc.)
- find balance between too many false positive and false negative
- edit ES artifacts only with ES/configure/content/content management
- best : 1 search per vCPU, so use scheduling to stay at this ratio (max allowed = 4 searches per vCPU, but perf issues)

slide 202 : mltk_apply_upper doc

# Module 10 : creating correlation searches
slides 207+
- scheduling :
  - RT schedule = run at exact time or skip (!= than normal saved search)
  - continuous = run at exact time if possible, delay it if not possible but keep the time range
- tip : add investogation profiles to "create notable event" action
- slide 231 : export knowledge object to an app, **recommandation** : increment app name , **warning** : if increment and reexport and not all objects are not selected, it will erase them from app

# Module 11 : Asset & Identity Management
slides 235+
- SA-IdentityManagement
- identity and assets managed lookup changes : retroactive (need few minutes for changes to be applied retroactively)
- asset priority (1st priority on top of list) : if one asset is in multiple asset lookup, then take only the one with higest priority ; same for identity **if** assets/identity are not merged
- for asset/identity : option to enable case sensitivity, not recommended for most cases
- enable zone for asset (case where same ip in different network) : slide 252
- merge asset : slide 253
- correlation setup : choose to do correlation for all/some/none sourcetypes
- tip  : don't include all info on identity/asset, especially sensitive ones, personal address -> it too saves space of kvstore collection
- cidr matching : slide 269 : take the smallest range when merging as it's the most specific range
- tip : use watchlist for asset/identity, slide 271

# Module 12: Managing Threat Intelligence
slides 276+
- threat intel : compare all data in Splunk with list of known threat
- index=threat_activity -> threat intel DM
- threat intel types : slide 280 (lists, stix/taxi, openioc, custom)
- tip : use adaptive response action of correlation search to add custom IOC to threat intel
- generic intel src : slide 281 (enrich data but not a threat intel)

# Appendix
- troubleshoot guideline
- search DM tips
- one prem deployment guideline : min 16-cores, 32 GiB RAM
- do not use Monitoring console on ES SH
- **ES = increase of volumetry on indexer** : slides 323
- indexers : enable summary replication to improve perf of indexers
- disable search affinity
- acceleration of DM : ~x3.4 storage slide 325
- UC library (ESCU app) : slide 333
- event sequencing engine : slide 340 ; ~= transaction for events, but it's for correlation search ; sequence are then visible in incident review dashboard