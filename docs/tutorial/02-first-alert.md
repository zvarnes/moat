# 2. Your first alert

**Goal:** trigger a safe alert, triage it in Kibana, then work it as a case in IRIS, the full loop an analyst does many times a day. About 30 minutes.

## Trigger it

```bash
./moat lab canary
```

This sends one harmless web request that a moat test signature recognizes. The alert takes about **5 minutes** to appear: Suricata sees the request, the event is stored, and the detection rule runs every 5 minutes.

## Find it in Kibana

**Security → Alerts.** Make sure the **Status** filter (under the title) says **Open**. If it's empty, you're seeing closed alerts too, which is the most common source of confusion.

You should see **"moat TEST sensor canary (safe to trigger)"**, severity **high**.

## Triage: the four questions

Open the alert (the **⤢** expand icon on its row). For every alert, answer:

| Question | Where to look | For the canary |
| --- | --- | --- |
| **Who?** Which device | `source.ip`; match it to *Device names* on the dashboard | your moat box (or wherever you ran it) |
| **What?** What happened | rule name, `reason`, `url.original` | an HTTP request for `/moat-test-canary` |
| **Where?** Talking to what | `destination.ip`, domain, organization | example.com's web server |
| **Normal?** Expected for this device | the device's other activity (below) | yes, you just did it |

**See the device's other activity:** in the alert, choose **Take action → Investigate in Timeline**. Timeline is a scratchpad for investigations. Try adding a query in it: `source.ip : "<the device IP>"`.

**Pivot to the full picture:** copy the alert's `network.community_id`. Go to **Discover** and search:
```
network.community_id : "<paste it here>"
```
You'll see Suricata's alert **and** Zeek's record of the same connection: bytes, duration, the HTTP details. That pivot is one of the most useful moves in network investigation.

## Work it in IRIS

A minute or so after the alert appears in Kibana, the bridge forwards it to IRIS (medium severity and above).

1. Open **IRIS → Alerts**. Set **Filter → Status = New** to hide closed ones.
2. Open **"moat TEST sensor canary"**. Note:
   - **IOCs:** the destination IP, the full URL, the domain.
   - **Assets:** your device, named from DHCP when known.
   - **Source link:** jumps straight back to the alert in Kibana.
   - **Relationships → Show open alerts:** other alerts that share an IOC or asset. Run the lab twice and you'll see them linked.
3. **Escalate it to a case.** IRIS calls this *merging*: on the alert, click **Merge → Merge into a new case**. Give the case a title like "Tutorial: sensor canary". (**Merge into existing case** adds it to a case you already have.)
4. In the case:
   - add a **note**: what you found, e.g. "Expected test traffic from the moat host.";
   - add a **task**: "Confirm canary fires after sensor changes";
   - look at the **IOC** tab: the IOCs came across from the alert.
5. **Close the case** with a resolution (for this one: *not applicable / test*).

## Close the alert in Kibana

Back in Kibana, on the alert: **Take action → Mark as closed** (or select rows in the table and use the bulk actions). In IRIS, an alert you *don't* escalate is closed with **Close** or **Close with note**. The Kibana alert and the IRIS alert are tracked separately. Close both, or pick one place to work and stick to it.

## What you just learned

- Detection is a pipeline: **sensor → stored event → rule → alert → (IRIS)**. The canary tests all of it; run it any time something changes.
- Triage is four questions: *who, what, where, normal?*
- `community_id` joins Suricata's and Zeek's views of the same connection.
- Kibana is for triage; IRIS is for anything that needs a record, tasks or evidence.

Next: [3. Hunting 101 →](03-hunting.md)
