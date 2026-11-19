# SPDX-License-Identifier: AGPL-3.0-only
"""Rebuild the Figma SVG exports: layer names, exact font weights, embedded font subsets.

Usage: python3 -I scripts/figma-reference-screens.py <raw-dir> <out-dir> <nodes.json> <map.tsv> <fonts-dir>
"""
import base64
import html
import io
import json
import os
import re
import sys
import xml.dom.minidom

from fontTools import subset
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

raw_dir, out_dir, nodes_path, map_path, fonts_dir = sys.argv[1:6]
names = dict(l.rstrip("\n").split("\t") for l in open(map_path, encoding="utf-8"))
nodes = json.load(open(nodes_path, encoding="utf-8"))["nodes"]

# Exact text styles from the Figma document, by node id.
weight_of = {}
family_of = {}


def walk(n):
    if n.get("type") == "TEXT":
        weight_of[n["id"]] = int(n["style"]["fontWeight"])
        family_of[n["id"]] = n["style"]["fontFamily"]
    for ch in n.get("children", []):
        walk(ch)


for v in nodes.values():
    walk(v["document"])

# Inter: optical size pinned to 14 (text), weight axis kept over the weights the file uses.
used = sorted({w for i, w in weight_of.items() if family_of[i] == "Inter"})
inter_base = TTFont(os.path.join(fonts_dir, "Inter-Variable.ttf"))
inter_base = instancer.instantiateVariableFont(inter_base, {"opsz": 14, "wght": (min(used), max(used))})
inter_buf = io.BytesIO()
inter_base.save(inter_buf)
inter_bytes = inter_buf.getvalue()
plex_bytes = open(os.path.join(fonts_dir, "IBMPlexMono-Regular.ttf"), "rb").read()


def woff2_subset(font_bytes, text):
    font = TTFont(io.BytesIO(font_bytes))
    options = subset.Options()
    options.flavor = "woff2"
    options.layout_features = ["*"]
    options.name_IDs = ["*"]  # keep the copyright and licence records (OFL)
    options.notdef_outline = True
    sub = subset.Subsetter(options)
    sub.populate(text=text)
    sub.subset(font)
    out = io.BytesIO()
    font.flavor = "woff2"
    font.save(out)
    cmap = font.getBestCmap()
    return out.getvalue(), {c for c in text if ord(c) not in cmap and not c.isspace()}


def fix_mojibake(value):
    # Figma writes layer names as the UTF-8 bytes of each character, one entity per byte.
    def repl(m):
        nums = [int(x) for x in re.findall(r"&#(\d+);", m.group(0))]
        if any(n > 255 for n in nums):
            return m.group(0)
        try:
            text = bytes(nums).decode("utf-8")
        except UnicodeDecodeError:
            return m.group(0)
        return html.escape(text, quote=True)

    return re.sub(r"(?:&#\d+;)+", repl, value)


TEXT_TAG = re.compile(r"<text\b[^>]*>")
report = []
for node_id, name in names.items():
    svg = open(os.path.join(raw_dir, name + ".svg"), encoding="utf-8").read()
    svg = re.sub(r'\sid="([^"]*)"', lambda m: ' id="' + fix_mojibake(m.group(1)) + '"', svg)

    def set_weight(m):
        tag = m.group(0)
        nid = re.search(r'data-node-id="([^"]+)"', tag).group(1)
        weight = weight_of[nid]
        tag = re.sub(r'\sfont-weight="[^"]*"', "", tag)
        return tag[:-1] + f' font-weight="{weight}">'

    svg = TEXT_TAG.sub(set_weight, svg)

    # The characters each family draws in this file.
    chars = {"Inter": set(), "IBM Plex Mono": set()}
    for m in re.finditer(r"(<text\b[^>]*>)(.*?)</text>", svg, re.S):
        family = re.search(r'font-family="([^"]+)"', m.group(1)).group(1)
        content = html.unescape(re.sub(r"<[^>]+>", "", m.group(2)))
        chars[family].update(content)
    faces, missing = [], {}
    for family, font_bytes, weight in (("Inter", inter_bytes, f"{min(used)} {max(used)}"), ("IBM Plex Mono", plex_bytes, "400")):
        if not chars[family]:
            continue
        data, lost = woff2_subset(font_bytes, "".join(sorted(chars[family])))
        if lost:
            missing[family] = "".join(sorted(lost))
        faces.append(
            f'@font-face{{font-family:"{family}";font-style:normal;font-weight:{weight};'
            f'src:url(data:font/woff2;base64,{base64.b64encode(data).decode()}) format("woff2");}}'
        )
    notice = (
        "<!-- Figma: OpenBastion (yUuwYSnGX7kSLzYX2rZXIU), node " + node_id + ". Embedded font subsets: "
        "Inter 4.001 (SIL OFL 1.1, Copyright 2020 The Inter Project Authors) and IBM Plex Mono "
        "(SIL OFL 1.1, Copyright 2017 IBM Corp., Reserved Font Name \"Plex\"); licences in fonts/. -->"
    )
    style = "<defs><style>" + "".join(faces) + "</style></defs>"
    svg = re.sub(r"(<svg\b[^>]*>)", lambda m: m.group(1) + "\n" + notice + "\n" + style, svg, count=1)
    xml.dom.minidom.parseString(svg.encode("utf-8"))  # well-formed, or fail
    with open(os.path.join(out_dir, name + ".svg"), "w", encoding="utf-8") as f:
        f.write(svg)
    report.append((name, len(svg.encode("utf-8")), missing))

for name, size, missing in report:
    print(f"{size:>8} {name} {missing if missing else ''}")
print("TOTAL", sum(s for _, s, _ in report))
