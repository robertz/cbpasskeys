"""Line coverage of the module's CFML from Lucee ResourceExecutionLog files.
A code line inside a function is covered when an executed statement starts on it, or it
continues a multi-line simple statement (no control keyword) that was executed. Lines
outside functions (the pseudo-constructor) aren't logged by Lucee and aren't counted.
usage: python3 scripts/coverage.py <exelog dir> <file suffix>..."""
import sys, os, re, bisect, collections

logdir, wanted = sys.argv[1], sys.argv[2:]
spans = collections.defaultdict(set)
for name in os.listdir(logdir):
    text = open(os.path.join(logdir, name), errors="replace").read().split("\n")
    if "" not in text:
        continue
    i = text.index("") + 1
    ids = {}
    while i < len(text) and text[i]:
        k, p = text[i].split(":", 1)
        ids[k] = p
        i += 1
    for line in text[i + 1:]:
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] in ids:
            spans[ids[parts[0]]].add((int(parts[1]), int(parts[2])))

skip = re.compile(r"^\s*(\}|\{|\)|\]|\};?|\);?|\]\s*\)?;?|\} else \{|else \{|case [^:]+:|default:|/\*\*.*|\*.*|//.*|component.*|interface.*|property .*|(public |private )?[\w ]*function .*\{|try \{|\} catch .*\{|\} finally \{)?\s*$")
total_missing = 0
for path in sorted(p for p in spans if any(p.endswith(w) for w in wanted)) + [w for w in wanted if not any(p.endswith(w) for p in spans)]:
    if not os.path.exists(path):
        print(f"{path}: never loaded")
        total_missing += 1
        continue
    src = open(path).read()
    starts = [0] + [m.end() for m in re.finditer("\n", src)]
    line_of = lambda pos: bisect.bisect_right(starts, pos)
    covered = set()
    ss = sorted(spans[path])
    lines = src.split("\n")
    control = re.compile(r"^\s*(\}\s*)?(if|else|for|while|switch|do|try|catch|lock|transaction|return\s*$)\b")
    for s, e in ss:
        first = line_of(s)
        covered.add(first)
        if not control.match(lines[first - 1]):
            covered.update(range(first, line_of(e) + 1))
    # lines inside function bodies only, and each multi-line statement's continuation lines
    depth, body_depth, inside, start_of = 0, None, set(), {}
    current = None
    for n, text in enumerate(lines, 1):
        t = text.strip()
        if body_depth is not None and depth > body_depth:
            inside.add(n)
            if t and not t.startswith(("//", "*", "/*")):
                if current is None:
                    current = n
                start_of[n] = current
                if t.endswith((";", "{", "}")) or control.match(text):
                    current = None
        if body_depth is None and re.search(r"\bfunction\s+\w+\s*\(", text):
            body_depth = depth
        depth += text.count("{") - text.count("}")
        if body_depth is not None and depth <= body_depth:
            body_depth, current = None, None
    for n, first in start_of.items():
        if first in covered:
            covered.add(n)
    in_comment = False
    missing = []
    for n, text in enumerate(lines, 1):
        t = text.strip()
        if t.startswith("/*"):
            in_comment = "*/" not in t
            continue
        if in_comment:
            in_comment = "*/" not in t
            continue
        if not t or skip.match(text) or n not in inside:
            continue
        if n not in covered:
            missing.append((n, t))
    in_comment, counted = False, 0
    for n, text in enumerate(lines, 1):
        t = text.strip()
        if t.startswith("/*") or in_comment:
            in_comment = "*/" not in t
            continue
        if t and not skip.match(text) and n in inside:
            counted += 1
    total_missing += len(missing)
    print(f"{os.path.basename(path)}: {counted - len(missing)}/{counted} lines covered")
    for n, t in missing:
        print(f"  {n}: {t}")
sys.exit(1 if total_missing else 0)
