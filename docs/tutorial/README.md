# moat tutorial: from `./moat up` to working like an analyst

A hands-on course in using your home SOC. Each chapter takes 15–30 minutes and ends with something you've actually done, not just read. No prior security experience needed; if you've worked in a SOC, skim chapters 1–2 and start at 3.

Every exercise uses **safe, repeatable triggers** (`./moat lab …`), so what you see matches what's written here. None of them touch the internet in a risky way.

## Before you start

- moat is running: `./moat status` shows a green cluster and agents online.
- You have your logins: `./moat creds`.
- For the network chapters, the sensor is set up (`SENSOR_IFACE` in `.env`), and the box running moat sends its own traffic across the mirrored link. If it doesn't, run the commands the labs print from any device that does.

## Chapters

| # | Chapter | You'll be able to… |
| --- | --- | --- |
| 1 | [A first look](01-first-look.md) | log in, check health, and read the dashboard |
| 2 | [Your first alert](02-first-alert.md) | trigger an alert, triage it in Kibana, and work it as a case in IRIS |
| 3 | [Hunting 101](03-hunting.md) | answer "what is this device doing?" in Discover |
| 4 | [Threat intel](04-threat-intel.md) | see how feeds turn a DNS lookup into a high-severity alert |
| 5 | [Your first detection](05-first-detection.md) | write a Sigma rule, test it and deploy it |
| 6 | [Tuning noise](06-tuning.md) | decide what to silence and how, without creating blind spots |
| 7 | [A routine that sticks](07-routine.md) | know what to check daily and weekly in 10 minutes |

## The one idea to keep in mind

moat collects **evidence** (every connection, DNS lookup and router event) and raises **alerts** only for a small, high-value slice of it. Alerts point you somewhere. The evidence is where you find out what actually happened. The whole tutorial is about moving between the two.

Reference docs, once you're done: [hunting-101](../hunting-101.md) · [writing-detections](../writing-detections.md) · [case-management](../case-management.md) · [threat-intel](../threat-intel.md)
