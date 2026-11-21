# Customer discovery kit (3 Customer Test)

Who to talk to, in order of value: a SOC or incident-response analyst at an NBFC, fintech or bank; their CISO or head of
information security; an IT infrastructure admin at the same kind of firm; an MSSP analyst. Mentors count only if they
belong to one of these segments.

**Keep separate:** research done before the finale (label it "prior research") and conversations held during the
finale (label them "finale interview", with date and time). Never write down an answer that was not given.

## 15-minute script

Opening (30 s): "We are building a tool for small security teams. I am not selling anything; I want to understand how
you investigate incidents today. Can I take notes? I will not name you or your company without permission."

1. Walk me through the last real incident you investigated. What happened first?
2. Which tools did you open, in what order? (SIEM, EDR, firewall console, spreadsheets, scripts?)
3. How long did it take to know which machines and accounts were affected? What was the slowest part?
4. Have you had to file a CERT-In report, an RBI CSIR form or a similar regulator report? How long did the first
   draft take, and what was hard to fill in?
5. When you tell management "these systems were reached", how do you show the evidence?
6. Would physical events (USB devices, console logins in the server room) have helped in any incident you remember?
7. What do you use today instead of a graph view of an attack? Why that?
8. *(Show the demo for 3 minutes: incident → attack path → blast radius → regulator draft.)* What is wrong or missing?
9. What would have to be true before you used this on real data? (Deployment, data residency, integrations, price.)
10. Who would approve buying a tool like this, and from which budget? Roughly what is spent today on investigation
    tooling? Would ₹2.4 lakh a year for up to 5 analysts be cheap, fair or too much? *(Unvalidated price hypothesis.)*
11. Can we follow up, and is there someone else we should talk to?

## Record template (one per person)

| Field | Answer |
|---|---|
| Date, time, channel (call / video / in person) | |
| Role and type of organisation (no name without permission) | |
| Segment (SOC analyst / CISO / IT admin / MSSP / other) | |
| Prior research or finale interview | |
| What we assumed before talking to them | |
| What we found out (their words where possible) | |
| Time to scope their last incident | |
| Tools used today | |
| Regulator reporting experience | |
| Who approves and pays | |
| Reaction to the price hypothesis | |
| What we changed in the product, or will change | |
| Follow-up agreed | |

## What the brief requires from this

For each of at least three people: what you assumed, what you found out, what you changed. These rows feed the Market
Fit Canvas (problem validation, current alternative, first user and payer) and must be traceable to the person.
