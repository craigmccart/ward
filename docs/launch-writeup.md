<!-- ward-allow-file: io.*, role.*, exf.*, tool.*, ait.*, obf.* -->

# I built an AI code reviewer, then attacked it. Here is what I built to stop it getting owned.

I built a deliberately naive AI reviewer agent and gave it a malicious pull request. With nothing in front of it, it approved that PR in 5 of 6 cases. With Ward in front, it approved 0 of 6, because it never read the payload in the first place.

This is the story of how I got there, and why the honest version of that story, naive reviewer and all, matters more than the impressive one.

## The lab came first

I did not set out to build a product. I set out to build a lab.

I wanted an agentic DevSecOps setup I could actually break. So I stood one up, wired an AI code reviewer in as the thing doing the reviewing, and then started attacking that reviewer the way people were attacking real AI reviewers through the first half of 2026.

Because 2026 was a bad year for trusting your metadata.

- **ambient-code, February.** An attacker swapped out a repo's `CLAUDE.md`, the file Claude Code loads as trusted instructions, and pointed it at vandalising the repo and posting a fake approval. Claude caught it that time. It should not have had to.
- **The Claude Code GitHub Action CVE**, disclosed June, fixed in Claude Code 2.1.128. A crafted GitHub issue body walked the agent into running commands that leaked environment variables.
- **Snyk's "Clinejection" writeup.** One issue title, one prompt-injection payload, and the Cline reviewer published malicious npm packages.
- **The "hackerbot-claw" GitHub Actions attacks, February.** These two were not prompt injection, they were bash-into-workflow. But they hit Microsoft's ai-discovery-agent through a branch name and DataDog's iac-scanner through a filename. The lesson still lands: your metadata is an attack surface now.

The common thread is the uncomfortable one. Every payload landed somewhere your SAST, your secret scanner and your prompt firewall are not looking. Branch names. Commit messages. PR titles and bodies. Filenames. Comments.

OWASP's Agentic Security Initiative Top 10 even has a name for it, ASI01, goal hijack through untrusted input. It names the pattern. It ships no tooling.

## So I built the layer that was missing

Ward is a pre-agent metadata scanner. It reads the untrusted text an AI reviewer is about to ingest, branch names, commits, PR titles and bodies, filenames, comments, docs, and it screens that text **before** it reaches the model.

That "before" is the whole point. Ward does not sit at the LLM boundary like Lakera or LlamaFirewall. It does not scan your source like SAST. It is an earlier layer than either. Defence in depth, not a replacement for anything you already run.

It is a Python CLI (the `ward` command), a GitHub Action, a pre-commit hook, and a small SDK. Output is pretty terminal text, JSON, or SARIF so findings land in your GitHub Code Scanning tab. MIT licence. Zero telemetry. It pairs with my other tool, Quell, and comes out of Sonofg0tham.

Under the hood there are two tiers.

**Tier one is a regex engine.** 49 rules across six categories (instruction override, role manipulation, obfuscation, tool-call injection, exfiltration, and AI-tool-specific), multilingual across nine languages. Fast, offline, deterministic, and free to run on every PR.

It is not naive about evasion either. It folds homoglyphs (the Cyrillic and Greek lookalikes), collapses repeat letters and intra-word separators like `i.g.n.o.r.e`, handles leetspeak, spots Unicode TAG-block payloads in the U+E0000 range, and recursively decodes base64, hex, URL-encoding, HTML entities and quoted-printable.

One honest gap: the all-single-space case, `i g n o r e`, gets past it. That is documented as out of scope, not swept under the rug.

**Tier two is an optional LLM judge.** Off by default. Ward's core has no LLM dependency at all. When you turn it on, it catches the semantic cases regex will never structurally see, paraphrases, role-play, novel phrasings, on a cheap Haiku-tier model. And the judge is hardened against being injected by the very text it is judging: the untrusted input is fenced with a one-time hash-derived delimiter the attacker cannot forge, every instruction lives in a cached system prompt, and the model can only return a structured verdict. That is defence in depth, not a guarantee, and the docs say exactly that.

## I published what Ward misses

Most security tools tell you their catch rate. Almost none tell you their miss rate. `ward bench` does.

It runs against four public corpora, each redistributed under its own MIT or Apache 2.0 licence: Lakera ignore-instructions, deepset prompt-injections, Spikee jailbreaks, and AdvBench harmful-behaviors.

```bash
ward bench --download    # fetches and scores all four public corpora
```

Here are the numbers, warts and all:

- **75.2%** in-scope recall on the bundled 50-row smoke samples.
- **53.5%** in-scope recall on the full corpora, 1,391 real rows across the three in-scope datasets (Lakera, deepset and Spikee). That is 561 of 1,048 injection-labelled rows caught.
- **0.0%** false-positive rate, measured on the 343 labelled benign rows in deepset. That is the number I am proudest of. A scanner that cries wolf gets turned off.
- **0%** on AdvBench, by design. AdvBench is 520 bare harmful-intent strings with no injection phrasing. It is a deliberate ceiling test, not a target. Ward is not meant to fire on it, and reporting that honestly is the point, not a regression to hide.

Every release commits its own benchmark report, so you can audit how the detection envelope moves version to version. CI posts a bench-diff comment on every PR.

## The centrepiece: `ward lab review`

This is the bit the whole lab was built for.

It puts a reviewer agent behind Ward and runs each malicious PR two ways. Unprotected, the reviewer ingests the raw metadata. Ward-protected, Ward screens it first.

The reviewer in these numbers is deliberately naive. It is a deterministic offline stand-in that does what the metadata tells it, so you can reproduce the exact result below in one command with no API key. That is on purpose, not a shortcut. You can also point the lab at a real Claude reviewer with `--reviewer anthropic`, which is more robust and will resist more of these. I come back to why that does not change the argument.

On the six bundled malicious-PR scenarios, offline and deterministic:

```
$ ward lab review
Ward:             6/6 blocked before the reviewer's context was populated
Reviewer, naked:  approved the malicious PR in 5/6 cases
Reviewer, warded: 0/6
```

Now the honest framing, because this is where security marketing usually lies to you.

Two caveats up front. That reviewer is a naive stand-in, not a real model, so its 5/6 is a demonstration of the mechanism, not a measurement of how often Claude or GPT gets owned. And I am **not** claiming a real model always gets hijacked. Modern models often resist, and sometimes they resist very well. If I told you the reviewer gets owned every single time, I would be selling you fear.

Here is the real claim, and it does not depend on the reviewer being gullible. With Ward, the injection is refused before the reviewer's context is ever populated. That is deterministic, offline, model-agnostic and provable. Without Ward, whether the model holds the line is up to the model on the day, and that is the gamble. Ward does not make the model braver. It turns "hope the model resists" into "the model never sees it".

## What Ward does not do

Same honesty, applied to the limits. Ward's `SECURITY.md` lists these plainly, so I will too. Ward does not catch:

- GCG adversarial suffixes
- AutoDAN and PAIR paraphrases
- Crescendo multi-turn jailbreaks
- Payload splitting
- ASCII-art payloads
- Multimodal (image) payloads
- Indirect injection through RAG or external content

For several of the semantic classes, the optional judge tier is the intended answer, and even then it is one layer, not a force field. Ward is one defensive layer. It is not a complete solution, and anyone who tells you their single tool is one is selling something.

## Try it

Ward is on PyPI (`pip install ward-scanner`), and the source is public at [github.com/craigmccart/ward](https://github.com/craigmccart/ward).

The GitHub Action is the fastest way to see it work, and it is listed on the [GitHub Marketplace](https://github.com/marketplace/actions/ward-pre-agent-metadata-scanner):

```yaml
- uses: sonofg0tham/ward@v0.3.2
  with:
    fail-on: high
```

There is also a pre-commit hook and a Python SDK if you want to wire it in yourself:

```python
from ward import build_input, scan_inputs, load_rule_pack
from ward.judge import get_judge
```

## The one line I actually want you to keep

Your AI reviewer might resist a prompt injection buried in a branch name. It might not. Ward's job is to make sure that question never comes up, because the payload gets stopped before the model reads a single character of it.

That is the diff. 5 of 6, down to 0 of 6, and the only thing that changed is a layer that runs first. I have shown you exactly what Ward catches and exactly what it does not, because in security a tool you can trust is worth more than a tool that sounds impressive.