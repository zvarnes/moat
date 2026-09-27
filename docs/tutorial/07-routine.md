# 7. A routine that sticks

**Goal:** a small habit that keeps moat useful. A SOC that nobody looks at is just a log archive.

## Daily: 5–10 minutes

1. **`./moat status`**: green, agents online, bridge polling.
2. **Security → Alerts, Status = Open.** Triage each alert with the four questions (*who, what, where, normal?*), then close it with a reason or escalate it to IRIS.
3. **IRIS → Alerts, Status = New.** Same queue, case-management side. Keep the two in step, or pick one to work from.

If there's nothing open, that's a good day. Don't go looking for problems every day.

## Weekly: about 30 minutes

1. **Dashboard, last 7 days.** Anything new compared to your baseline from chapter 1? A new device, a new country, a device whose traffic jumped?
2. **One hunt** from chapter 3, on one device. Rotate through your devices over the weeks.
3. **Tuning check** (chapter 6): the noisiest rule of the week. Fix it precisely, or leave it.
4. **Run the canary** (`./moat lab canary`) to prove the pipeline still works end to end.

## Monthly

- **Update:** `git pull`, `./moat init --add-missing`, then `./moat up`. New moat versions may add settings; `--add-missing` fills them in without touching yours.
- **Review `disable.conf` and your rule exceptions.** Is each still needed?
- **Browse the community rules:** Security → Rules, filter by the tag `Sigma: sigmahq`. Enable any that fit your network.

## When something looks wrong

1. **Don't panic, and don't unplug anything yet.** Evidence first.
2. **Open an IRIS case.** Write down what you saw and when.
3. **Scope it:** which device? Since when? What else did it talk to? (chapter 3)
4. **Contain if needed:** block the device on your router, then keep investigating from moat's records.
5. **Close with a resolution and a lesson.** Did a rule catch it? Should one? (chapter 5)

## Where to go from here

- **Add endpoints:** `./moat enroll` puts Elastic Defend on a laptop or server, adding process, file and login visibility on top of the network.
- **Learn the rule languages properly:** [Sigma docs](https://sigmahq.io/docs/basics/rules.html), [Suricata rules](https://docs.suricata.io/en/latest/rules/).
- **Practice on real attack traffic:** public PCAPs (e.g. from malware-traffic-analysis.net) are how analysts train. A future moat lab will replay them safely.

That's the course. You now run your own SOC.
