#!/usr/bin/env python3
"""Builds readme.html from readme.md.

readme.md is SAZU's single source of truth for the design document;
readme.html is a styled, generated rendering of it, not a second copy
maintained by hand. Mirrors the reasoning behind the YAML -> HTML
pipeline in plugin/sazu/verification of the Go/CoreDNS port this
project has been built against: two hand-maintained copies of the same
content drift apart, silently, in a way nobody notices until it's
already wrong. A generator can't drift -- it re-derives the rendering
from the source every time.

Usage:
    .venv/bin/python build.py [--out PATH] [--src PATH]

See README.md in this directory for the markdown conventions this
expects (callouts, inline code, numbered subsections) and how to add a
new one if the design document needs a shape this doesn't handle yet.
"""
import argparse
import pathlib
import re

import jinja2
import markdown
from bs4 import BeautifulSoup, Tag

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent

# A top-level section heading: "## 4. Two independent design axes".
# Only ## (not ###/####) headings split the document into <section>s --
# see README.md's "Heading levels" for why.
SECTION_RE = re.compile(r"^## (\d+)\.\s+(.+)$", re.MULTILINE)

# A numbered subsection heading's own text, once markdown has already
# turned "### 10.9 Title" into an <h3>: "10.9 Title" -> ("10.9", "Title").
SUBHEADING_RE = re.compile(r"^([\d]+(?:\.[\d]+)*)\s+(.*)$")

MARKDOWN_EXTENSIONS = ["tables", "fenced_code", "sane_lists"]


def slugify(title: str) -> str:
    s = title.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")


def split_sections(body_md: str):
    """Splits body_md (everything from the first "## N. Title" onward)
    into a list of (number, title, raw_markdown) per top-level section."""
    matches = list(SECTION_RE.finditer(body_md))
    sections = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body_md)
        sections.append((m.group(1), m.group(2).strip(), body_md[start:end].strip()))
    return sections


def _is_lone_strong_paragraph(node) -> bool:
    """True for a <p> whose entire content is one <strong> -- the
    source's "> **Label**" own-line convention that marks where a new
    callout starts."""
    if not isinstance(node, Tag) or node.name != "p":
        return False
    kids = list(node.children)
    return len(kids) == 1 and isinstance(kids[0], Tag) and kids[0].name == "strong"


def promote_callouts(soup: BeautifulSoup) -> None:
    """Each "> **Label**\\n>\\n> body..." run becomes
    <div class="callout"><span class="label">Label</span>body...</div>.
    Markdown's own blockquote parser merges two adjacent "> ..." runs
    separated only by a blank line into one <blockquote> rather than
    two -- exactly the shape two consecutive callouts in this document
    take in the source -- so a single <blockquote> here may actually
    contain several callouts back to back. Split it at every lone-bold
    paragraph, not just its first child, and emit one callout div per
    group, in order; a blockquote with no such marker at all becomes a
    single unlabeled callout div (a signal to check the source, since
    every callout in this document is written the labeled way on
    purpose -- see README.md)."""
    for bq in soup.find_all("blockquote"):
        groups: list[list] = [[]]
        for child in list(bq.children):
            if _is_lone_strong_paragraph(child):
                groups.append([child])
            else:
                groups[-1].append(child)
        # Drop any group with no actual element in it -- just the
        # whitespace NavigableStrings markdown leaves between a
        # blockquote's block-level children, most commonly a leading
        # one before the first real paragraph.
        groups = [g for g in groups if any(isinstance(c, Tag) for c in g)]

        divs = []
        for group in groups:
            div = soup.new_tag("div", **{"class": "callout"})
            first = group[0]
            if _is_lone_strong_paragraph(first):
                label = soup.new_tag("span", **{"class": "label"})
                label.string = list(first.children)[0].get_text()
                div.append(label)
                rest = group[1:]
            else:
                rest = group
            for c in rest:
                div.append(c.extract())
            divs.append(div)

        if not divs:
            bq.decompose()
        elif len(divs) == 1:
            bq.replace_with(divs[0])
        else:
            bq.replace_with(divs[0])
            anchor = divs[0]
            for div in divs[1:]:
                anchor.insert_after(div)
                anchor = div


def mark_inline_code(soup: BeautifulSoup) -> None:
    """Every <code> not inside a <pre> block is inline code (a name,
    status code, or short snippet in running text) -- give it the
    "inline" class the stylesheet expects; a <pre><code> block (a
    diagram or JSON example) is left alone."""
    for code in soup.find_all("code"):
        if code.parent is not None and code.parent.name == "pre":
            continue
        existing = code.get("class", [])
        code["class"] = existing + ["inline"]


def mark_plain_lists(soup: BeautifulSoup) -> None:
    for ol in soup.find_all("ol"):
        existing = ol.get("class", [])
        ol["class"] = existing + ["plain"]


def promote_subheadings(soup: BeautifulSoup) -> None:
    """"### 10.9 Title" markdown becomes, after conversion, an <h3>
    whose text is "10.9 Title" -- split that into the same
    <span class="num">10.9</span> Title shape the top-level <h2>s use,
    so a numbered subsection reads consistently at either level. h4 is
    handled the same way in case a future section needs one more level
    of nesting than any current section does."""
    for level in ("h3", "h4"):
        for h in soup.find_all(level):
            m = SUBHEADING_RE.match(h.get_text())
            if not m:
                continue
            h.clear()
            num = soup.new_tag("span", **{"class": "num"})
            num.string = m.group(1)
            h.append(num)
            h.append(" " + m.group(2))


def render_section(number: str, title: str, raw_md: str) -> tuple[str, str]:
    html = markdown.markdown(raw_md, extensions=MARKDOWN_EXTENSIONS)
    soup = BeautifulSoup(html, "html.parser")
    promote_callouts(soup)
    mark_inline_code(soup)
    mark_plain_lists(soup)
    promote_subheadings(soup)
    slug = slugify(title)
    inner = "".join(str(c) for c in soup.contents)
    section_html = (
        f'    <section id="{slug}">\n'
        f"      <h2><span class=\"num\">{number}</span> {title}</h2>\n"
        f"{inner}\n"
        f"    </section>"
    )
    return slug, section_html


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(ROOT / "readme.md"))
    ap.add_argument("--out", default=str(ROOT / "readme.html"))
    args = ap.parse_args()

    text = pathlib.Path(args.src).read_text(encoding="utf-8")
    first = SECTION_RE.search(text)
    if not first:
        raise SystemExit(f"{args.src}: no top-level '## N. Title' section found")
    body_md = text[first.start():]

    toc = []
    sections_html = []
    for number, title, raw_md in split_sections(body_md):
        slug, section_html = render_section(number, title, raw_md)
        toc.append((number, title, slug))
        sections_html.append(section_html)

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(HERE)),
        autoescape=False,
        keep_trailing_newline=True,
    )
    template = env.get_template("template.html.j2")
    html = template.render(toc=toc, sections_html="\n\n".join(sections_html))

    out_path = pathlib.Path(args.out)
    out_path.write_text(html, encoding="utf-8")
    print(f"wrote {out_path} ({len(html)} bytes), {len(toc)} sections")


if __name__ == "__main__":
    main()
