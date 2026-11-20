#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The Prover SDK's API reference, docs/sdk-api-reference.md, generated from sdk/include/aegis_sdk.h.

The header is the reference: every macro, result code, structure member and function in it, with the comment the
header gives it, in the header's order. Nothing is written by hand in the generated file, so the two cannot drift;
tests/host/test_sdk_docs.py runs --check.

  tools/gen_sdk_api_ref.py            write docs/sdk-api-reference.md
  tools/gen_sdk_api_ref.py --check    exit 1 if the file is not what the header gives
"""
import argparse
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
HEADER = os.path.join(ROOT, "sdk", "include", "aegis_sdk.h")
OUT = os.path.join(ROOT, "docs", "sdk-api-reference.md")


def comment_text(raw):
    """The text of a C block comment (with or without its delimiters), its lines joined into paragraphs."""
    raw = raw.strip()
    if raw.startswith("/*"):
        raw = raw[2:]
    if raw.endswith("*/"):
        raw = raw[:-2]
    lines = []
    for ln in raw.split("\n"):
        ln = ln.strip()
        if ln.startswith("*"):
            ln = ln[1:]
        if ln.strip().startswith("SPDX-License-Identifier"):
            continue
        lines.append(ln.rstrip())
    # keep indented lines (tables, lists in the comment) as they are, join the rest
    out, para = [], []
    for ln in lines:
        if ln.startswith("  ") and ln.strip():
            if para:
                out.append(" ".join(para))
                para = []
            if out and out[-1] and not out[-1].startswith("    "):
                out.append("")              # a code block in Markdown needs a blank line before it
            out.append("    " + ln[2:].rstrip())
        elif not ln.strip():
            if para:
                out.append(" ".join(para))
                para = []
            out.append("")
        else:
            if out and out[-1].startswith("    "):
                out.append("")
            para.append(ln.strip())
    if para:
        out.append(" ".join(para))
    text = "\n".join(out).strip("\n")
    return re.sub(r"\n{3,}", "\n\n", text)


def md_cell(text):
    return " ".join(text.split()).replace("|", "\\|")


def split_trailing(code):
    """'code /* c */' -> ('code', 'c'); a comment that runs on is returned open (its end is on later lines)."""
    i = code.find("/*")
    if i < 0:
        return code.rstrip(), None
    return code[:i].rstrip(), code[i:]


def parse(path=HEADER):
    with open(path) as f:
        src = f.read()
    lines = src.split("\n")
    items = []          # (kind, data) in header order
    pending = None      # the last block comment, for the declaration after it
    cond = None         # the #if a declaration is under
    i = 0

    def read_comment(start, first):
        """A comment that starts at lines[start] (from text `first`); returns (text, next line index)."""
        buf, j = [first], start
        while "*/" not in buf[-1]:
            j += 1
            buf.append(lines[j])
        return "\n".join(buf), j + 1

    while i < len(lines):
        ln = lines[i]
        s = ln.strip()
        if not s:
            i += 1
            continue
        m = re.match(r"/\* -{4} (.+?) -{3,}(.*)", s)
        if m:
            raw, i = read_comment(i, m.group(2))
            items.append(("section", {"title": m.group(1).strip(), "intro": comment_text(raw)}))
            pending = None
            continue
        if s.startswith("/*"):
            raw, i = read_comment(i, s)
            if not items:
                items.append(("preamble", comment_text(raw)))
            else:
                pending = comment_text(raw) if pending is None else pending + "\n\n" + comment_text(raw)
            continue
        if s.startswith("#if ") or s.startswith("#if\t"):
            cond = s[3:].strip()
            i += 1
            continue
        if s.startswith("#endif"):
            cond = None
            i += 1
            continue
        if s.startswith("#ifndef") or s.startswith("#include") or s.startswith("#endif"):
            i += 1
            continue
        m = re.match(r"#define\s+(\w+)(\([^)]*\))?\s*(.*)", s)
        if m:
            name, args, rest = m.group(1), m.group(2) or "", m.group(3)
            if name == "AEGIS_SDK_H":
                i += 1
                continue
            body = rest
            while body.endswith("\\"):
                i += 1
                body = body[:-1].rstrip() + " " + lines[i].strip()
            value, trail = split_trailing(body)
            if trail is not None and "*/" not in trail:
                trail, i = read_comment(i, trail)
                i -= 1
            doc = comment_text(trail) if trail else None
            items.append(("define", {"name": name + args, "value": " ".join(value.split()), "doc": doc,
                                     "lead": pending, "cond": cond}))
            pending = None
            i += 1
            continue
        m = re.match(r"(enum|struct)\s+(\w+)\s*\{", s)
        if m:
            kind, name = m.groups()
            members, mpending, j = [], None, i + 1
            while not lines[j].strip().startswith("};"):
                t = lines[j].strip()
                if not t:
                    j += 1
                    continue
                if t.startswith("/*"):
                    raw, j = read_comment(j, t)
                    mpending = comment_text(raw) if mpending is None else mpending + "\n\n" + comment_text(raw)
                    continue
                code, trail = split_trailing(t)
                if trail is not None and "*/" not in trail:
                    # a trailing comment that runs on over the next lines, each starting with "*"
                    k = j + 1
                    while "*/" not in trail:
                        trail += "\n" + lines[k].strip()
                        k += 1
                    j = k - 1
                doc = comment_text(trail) if trail else ""
                if mpending:
                    doc = (mpending + ("\n\n" + doc if doc else ""))
                    mpending = None
                if code:
                    members.append({"code": code.rstrip(",;"), "doc": doc})
                elif members and doc:
                    members[-1]["doc"] += " " + doc
                j += 1
            if kind == "enum":
                value = -1
                for mem in members:
                    mm = re.match(r"(\w+)(?:\s*=\s*(\d+))?", mem["code"])
                    value = int(mm.group(2)) if mm.group(2) else value + 1
                    mem["name"], mem["value"] = mm.group(1), value
            items.append((kind, {"name": name, "members": members, "doc": pending, "cond": cond}))
            pending = None
            i = j + 1
            continue
        # a function declaration, over one or more lines up to ';'
        if re.match(r"[A-Za-z_][\w\s\*]*\(", s) or re.match(r"(const\s+)?[\w]+\s*\*?\s*\w+\(", s):
            decl, j = s, i
            while not decl.rstrip().endswith(";"):
                j += 1
                decl += " " + lines[j].strip()
            decl = " ".join(decl.split())
            name = re.search(r"(\w+)\s*\(", decl).group(1)
            items.append(("function", {"name": name, "decl": decl, "doc": pending, "cond": cond}))
            pending = None
            i = j + 1
            continue
        raise ValueError("%s:%d: not understood: %s" % (path, i + 1, s))
    return items


def cond_note(cond):
    if not cond:
        return ""
    if "AEGIS_EAT_COSE" in cond:
        return " *(only with `-DAEGIS_EAT_COSE=1`)*"
    return " *(only if `%s`)*" % cond


def render(items):
    api = next(d["value"] for k, d in items if k == "define" and d["name"] == "AEGIS_SDK_API_VERSION")
    out = ["<!-- SPDX-License-Identifier: Apache-2.0 -->",
           "<!-- GENERATED by tools/gen_sdk_api_ref.py from sdk/include/aegis_sdk.h: do not edit; run the tool. -->",
           "# Prover SDK API reference",
           "",
           "API version **%s** (`AEGIS_SDK_API_VERSION`). Generated from [`sdk/include/aegis_sdk.h`]"
           "(../sdk/include/aegis_sdk.h), the one public header, in its order and with its own words; the header "
           "is authoritative. The integrator's guide is [`docs/sdk-porting-guide.md`](sdk-porting-guide.md), what "
           "may change between versions is in [`docs/sdk-versioning.md`](sdk-versioning.md)." % api.rstrip("u"),
           ""]
    toc = ["## Contents", ""]
    body = []
    defines = []
    seen_section = False

    def flush_defines():
        if not defines:
            return
        lead = defines[0]["lead"]
        if lead and len(defines) == 1 and not defines[0]["doc"]:
            defines[0] = dict(defines[0], doc=lead)
        elif lead:
            body.extend([lead, ""])
        body.extend(["| Macro | Value | Meaning |", "|---|---|---|"])
        for d in defines:
            doc = d["doc"] or ""
            body.append("| `%s`%s | `%s` | %s |" % (d["name"], cond_note(d["cond"]), md_cell(d["value"]),
                                                     md_cell(doc)))
        body.append("")
        defines.clear()

    for kind, d in items:
        if kind == "preamble":
            out.extend(["## Overview", "", d, ""])
            continue
        if kind == "section":
            seen_section = True
            flush_defines()
            title = d["title"][0].upper() + d["title"][1:]
            anchor = re.sub(r"[^a-z0-9 -]", "", title.lower()).replace(" ", "-")
            toc.append("- [%s](#%s)" % (title, anchor))
            body.extend(["## %s" % title, ""])
            if d["intro"]:
                body.extend([d["intro"], ""])
            continue
        if kind == "define":
            if not seen_section:
                seen_section = True
                toc.append("- [Version](#version)")
                body.extend(["## Version", ""])
            if d["lead"]:
                flush_defines()
            defines.append(d)
            continue
        flush_defines()
        if kind == "enum":
            body.extend(["### `enum %s`%s" % (d["name"], cond_note(d["cond"])), ""])
            if d["doc"]:
                body.extend([d["doc"], ""])
            body.extend(["| Value | Name | Meaning |", "|---|---|---|"])
            for mem in d["members"]:
                body.append("| %d | `%s` | %s |" % (mem["value"], mem["name"], md_cell(mem["doc"])))
            body.append("")
        elif kind == "struct":
            body.extend(["### `struct %s`%s" % (d["name"], cond_note(d["cond"])), ""])
            if d["doc"]:
                body.extend([d["doc"], ""])
            body.extend(["| Member | Meaning |", "|---|---|"])
            for mem in d["members"]:
                body.append("| `%s` | %s |" % (md_cell(mem["code"]), md_cell(mem["doc"])))
            body.append("")
        elif kind == "function":
            body.extend(["### `%s()`%s" % (d["name"], cond_note(d["cond"])), "", "```c", d["decl"], "```", ""])
            if d["doc"]:
                body.extend([d["doc"], ""])
    flush_defines()
    text = "\n".join(out + toc + [""] + body).rstrip("\n") + "\n"
    return re.sub(r"\n{3,}", "\n\n", text)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if the reference is not up to date")
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args(argv)
    text = render(parse())
    if a.check:
        try:
            with open(a.out) as f:
                same = f.read() == text
        except FileNotFoundError:
            same = False
        if not same:
            print("%s is not up to date with sdk/include/aegis_sdk.h: run tools/gen_sdk_api_ref.py" % a.out)
            return 1
        print("%s is up to date" % a.out)
        return 0
    with open(a.out, "w") as f:
        f.write(text)
    print("wrote %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
