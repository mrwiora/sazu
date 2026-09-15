# SAZU design document — build pipeline

`readme.html` — the styled rendering of the design document — is
**generated**, not hand-edited. `readme.md` is the single source of
truth; `build.py` renders it into `readme.html` through
`template.html.j2`. This mirrors the reasoning behind the YAML → HTML
pipeline in `plugin/sazu/verification` of the Go/CoreDNS port this
project has been built against: two hand-maintained copies of the same
content drift apart, silently, in a way nobody notices until it's
already wrong.

## Building

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python build.py
```

writes `../readme.html`. Pass `--src PATH` or `--out PATH` to read or
write somewhere else.

## How it works

`build.py` splits `readme.md` at each top-level `## N. Title` heading
into one section per number, converts each section's markdown to HTML
independently (via the `markdown` library: tables, fenced code blocks,
and lists are all handled by it directly), then post-processes the
result with BeautifulSoup to match `readme.html`'s existing visual
conventions:

- Each section becomes `<section id="auto-slugified-title"><h2><span
  class="num">N</span> Title</h2>...</section>`; the navigation (both
  the sidebar and the mobile `<details>` menu) is generated from the
  same list, so a new or renumbered section never needs updating in
  two places.
- A `### N.M Title` subheading becomes `<h3><span class="num">N.M</span>
  Title</h3>` — the same numbered-heading treatment one level down.
- `> **Label**\n>\n> body...` becomes `<div class="callout"><span
  class="label">Label</span>body...</div>`. **Non-obvious wrinkle:**
  Python-Markdown merges two `>`-quoted runs separated only by a blank
  line into *one* `<blockquote>`, not two — which is exactly the shape
  two consecutive callouts take in the source. `promote_callouts` in
  `build.py` splits a merged blockquote back into separate callout divs
  at every lone-bold-paragraph marker it finds, not just the first one;
  if a future edit adds a callout and it silently merges into its
  neighbor in the rendered output, this is the function to look at.
- Inline `` `code` `` gets `class="inline"`; a fenced code block does
  not (it's already `<pre><code>`, styled differently on purpose).
- Every `<ol>` gets `class="plain"`, matching the existing stylesheet's
  reset for numbered lists that shouldn't look like a numbered list
  (e.g. §10.2's two bootstrap checks).

## What's still hand-maintained

`template.html.j2` carries the page's `<head>` (fonts, the full color
system for light/dark mode, layout CSS) and the `<header>` block —
title, dek, status line, and the "Abstract"/"Why SAZU" callouts —
verbatim, unchanged by a `readme.md` edit. None of that is section
content the markdown source carries, so there's nothing to generate it
from; edit `template.html.j2` directly if any of it needs to change.

**Known simplification:** the original hand-authored `readme.html` gave
§7.2/7.3's "carrier A"/"carrier B" a small colored tag badge
(`<span class="tag standard">`) next to the heading. Nothing in
`readme.md`'s plain-text heading ("### 7.2 SAZU over raw DNS UPDATE —
carrier A") distinguishes that from ordinary heading text, and inventing
a non-standard markdown convention just to preserve two badges wasn't
judged worth it — the generated page renders that text plain instead.
Everything else (callouts, tables, code, numbered sections and
subsections) matches the original's visual treatment exactly, since
`template.html.j2` reuses its stylesheet verbatim.

## Adding a new top-level section or subsection

Just add `## 15. Title` (or `### N.M Title` inside an existing one) to
`readme.md` and rebuild — no other file needs touching. The only
requirement is the exact `## <number>. <title>` / `### <dotted-number>
<title>` heading shape `build.py`'s regexes expect; see `SECTION_RE` and
`SUBHEADING_RE` at the top of `build.py` if a heading isn't being picked
up.
