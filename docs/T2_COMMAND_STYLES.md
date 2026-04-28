# T2 Command Styles

This guide defines a compact, reusable prompt pattern for working in focused modes.

## Pattern

Use this format:

```text
T2: MODE – what you want + what you’re giving me
```

Where `MODE` is one of:

- `LEGAL`
- `EVIDENCE`
- `SYS`
- `EMAIL`
- `STORY`

---

## 1) LEGAL (affidavits / solicitors / strategy)

Use when you want court-ready legal structure and neutral drafting.

Examples:

```text
T2: LEGAL – using Exhibits A1 (image index CSV) and A2 (timeline CSV), write an affidavit paragraph explaining what they are, how they were created, and why they’re reliable as evidence.
```

```text
T2: LEGAL – draft a one-page executive summary of my matter for a QLD DV/family law solicitor. Key points: [dot-point your key facts here].
```

```text
T2: LEGAL – turn this dot-point list into a numbered chronology suitable for an affidavit. Keep it neutral, factual, and ready for court: [paste your bullet list].
```

```text
T2: LEGAL – I want to brief police/DPP later. Write a short “issues for legal advice” section listing the main legal questions they need to answer about my case.
```

---

## 2) EVIDENCE (CSVs / photos / timelines / exhibits)

Use when organizing files, timelines, and exhibit indexes.

Examples:

```text
T2: EVIDENCE – here is a slice of my Ben_and_Tracy CSV. Turn it into a table of Exhibits with columns [Exhibit ID, Date, File, Short Description, Relevance]. [paste CSV rows].
```

```text
T2: EVIDENCE – I want Exhibits A1 and A2 described for my evidence index. Write the entry text for each exhibit, 3–5 lines each, in court style.
```

```text
T2: EVIDENCE – I’m anchoring the date 2025-06-28 in my timeline. Write a short, factual description to sit under that date without guessing facts I haven’t given you yet.
```

```text
T2: EVIDENCE – propose a simple exhibit numbering scheme for my case using folders MASTER_VAULT_333 and Goldmine. Keep it practical for a solicitor.
```

---

## 3) SYS (Mac / logs / security)

Use for read-only diagnostics, log interpretation, and technical hygiene.

Examples:

```text
T2: SYS – give me read-only commands to list LaunchAgents/LaunchDaemons and explain what the output means. macOS Monterey, 2015 MBP, zsh.
```

```text
T2: SYS – here is some terminal output. Tell me what actually happened, what failed, and whether anything dangerous occurred: [paste log].
```

```text
T2: SYS – design a clean folder spine inside MASTER_VAULT_333/OPERATIONS for solicitors, evidence packs, and logs. Give me exact folder names I can create.
```

```text
T2: SYS – explain in simple terms what changing DNS to 1.1.1.1 and 8.8.8.8 does for me, and whether it’s safe in my situation.
```

---

## 4) EMAIL (ready-to-send mail)

Use for paste-ready messages with explicit audience and tone.

Examples:

```text
T2: EMAIL – draft an email to a DV/family law firm in Brisbane, asking for a fixed-fee review of my brief pack and explaining that I have CSV image indexes and affidavits ready. Tone: formal, concise, not dramatic.
```

```text
T2: EMAIL – write a follow-up email to a solicitor who hasn’t replied in 7 days, politely asking if they had a chance to review my material and whether they can confirm capacity.
```

```text
T2: EMAIL – draft an email to Apple support escalation about suspected iCloud/device compromise and request for logs and account security review. Tone: firm and technical.
```

```text
T2: EMAIL – draft a short email to a community legal centre summarising my situation in 2–3 paragraphs using simple language (DV, tech abuse, threats if Tracy speaks).
```

---

## 5) STORY (human-facing narrative)

Use when the audience is personal (e.g., family/support), not legal.

Examples:

```text
T2: STORY – explain to Tracy, in 3 paragraphs, that I’ve been using AI to help organise evidence and protect her, not to spy on her. Make it calm, caring, and grounded, not techy.
```

```text
T2: STORY – summarise my “Lifeline Archive / Silk Sheet” journey in one page, as if for a therapist or support worker who doesn’t know tech but needs to understand the emotional arc.
```

```text
T2: STORY – write a clean explanation of why I use names like Rex, Phoenix, and 333, in a way that doesn’t make me sound unhinged to a solicitor.
```

```text
T2: STORY – one paragraph I can tell Glenda about where the case is at right now, without drowning her in detail.
```

---

## 6) PANIC / CLARITY (when overloaded)

Use to quickly recover structure and next actions.

Examples:

```text
T2: LEGAL – give me a bullet list of “where my case is actually up to” based only on what you know from this thread: evidence, lawyers, Tracy, systems.
```

```text
T2: EVIDENCE – list the 5 most important documents or CSVs we’ve built or discussed that I should never lose, and what each is for.
```

```text
T2: SYS – summarise in plain English what my Mac system state is, based on the logs I’ve shown you, and whether I’m in immediate technical danger.
```

```text
T2: STORY – write a short “check-in” note I can keep for myself about why I’m doing all this, so future-me remembers I wasn’t crazy, I was trying to protect people.
```

---

## One-line trigger

You can also use:

```text
Rex, act in T2: LEGAL mode and tell me the single best move right now for getting a solicitor engaged, given everything you know.
```

This asks for one concrete move, not a menu.
