- https://www.reddit.com/r/cybersecurity/comments/x9h6ac/how_does_one_move_silently_through_a_network/ :
```
Bash-Monkey
·
il y a 8 h
· a modifié il y a 7 min
Bravo!Take My Energy

Going to assume you are on said network.

    Keep your footprint on the host minimal and tread carefully (not uploading every module of your malware to the box, drastically changing security policy, pissing off edr/logging/ defender...) - keeping your malware hidden, fileless is great!

    Send traffic that matches the type of traffic leaving the host, or at the very least fits in. A friend of mine wrote a RAT that uses reddit for encoded command and control. Not too crazy if it's a user's workstation. It looks like legitimate conversation.

    Randomize beaconing, exfil / command and control.There are awesome tools that will root out any noticably scheduled callbacks these days. My friend from earlier had his RAT callback at 3 random days of the work week, during random business hours.

    Exfil slowly. Send legit traffic, with 2 bytes as your payload out, or better yet encode it as keywords/codes that seem legit. Slowly and steady wins the race.

    Mind/research the target's security measures - if a machine is running Rsyslog, someone's going to notice if that box stops sending logs - Try to understand if the target will run research on you if caught

    If possible, try to "baseline" the target network (maybe just your current box) to find traffic to mimic

Even the best SOCs can't look at every interaction or connection. Craft traffic to match whatever the network looks like

A less custom way is through DNS exfil or simple SSL tunneling. These techniques work, but are highly expected from attackers. The more work you put in, the less likely you are to get caught. Determine if the juice is worth the squeeze
```