#!/usr/bin/env python3
"""Build a hand-annotation set from a real stress run.

Profile labels are NOT ground truth for individual log lines, so promotion/calibration data has
to be labelled by hand. This tool makes that small and leak-free.

usage:
  python3 scripts/make_annotation_set.py RUN/replay_dataset.jsonl annotate.tsv [--per-profile 40] [--seed 7]
  # fill column 2 of annotate.tsv by hand: healthy, early_rst, byte_freeze, pmtu_drop, throttle,
  # route_or_dns_fail, unrelated  (column 3 = profile, a hint only)
  python3 scripts/make_annotation_set.py --split annotate.tsv holdout.tsv dev.tsv [--holdout 0.5] [--seed 7]

* Lines are normalised (timestamps, hex ids, numbers -> placeholders) and de-duplicated per template.
* A template goes entirely to holdout or dev, never both (no near-duplicate leakage).
* holdout.tsv is in the `log<TAB>class` format of `khaymali promote-nlp-candidate`.
"""
import collections, json, random, re, sys

CLASSES = {"healthy", "early_rst", "byte_freeze", "pmtu_drop", "throttle", "route_or_dns_fail", "unrelated"}


def template(line):
    t = line.lower()
    t = re.sub(r"\d{4}-\d\d-\d\dt[\d:.]+z?", "<ts>", t)
    t = re.sub(r"0x[0-9a-f]+", "<hex>", t)
    t = re.sub(r"\b\d+(\.\d+)*\b", "<n>", t)
    return re.sub(r"\s+", " ", t).strip()


def opt(argv, name, default, cast):
    return cast(argv[argv.index(name) + 1]) if name in argv else default


def sample(src, dst, per_profile, seed):
    by = collections.defaultdict(dict)
    for line in open(src, encoding="utf-8"):
        if not line.strip():
            continue
        rec = json.loads(line)
        log = str(rec.get("log", "")).replace("\t", " ").strip()
        if log:
            by[rec.get("profile", "unknown")].setdefault(template(log), log)
    rnd = random.Random(seed)
    rows = []
    for prof in sorted(by):
        items = sorted(by[prof].items())
        rnd.shuffle(items)
        rows += [(log, prof, tpl) for tpl, log in items[:per_profile]]
    with open(dst, "w", encoding="utf-8") as out:
        out.write("# log\tclass(fill me)\tprofile(hint only)\ttemplate\n")
        for log, prof, tpl in rows:
            out.write(f"{log}\t\t{prof}\t{tpl}\n")
    print(f"{len(rows)} unique lines from {len(by)} profiles -> {dst}; fill column 2 by hand")
    return 0


def split(src, holdout_path, dev_path, frac, seed):
    groups, bad = collections.defaultdict(list), 0
    for line in open(src, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) < 2 or f[1].strip() not in CLASSES:
            bad += 1
            continue
        groups[f[3] if len(f) > 3 and f[3] else template(f[0])].append((f[0], f[1].strip()))
    keys = sorted(groups)
    random.Random(seed).shuffle(keys)
    cut = int(len(keys) * frac)

    def write(path, ks):
        rows = [r for k in ks for r in groups[k]]
        with open(path, "w", encoding="utf-8") as out:
            for log, cls in rows:
                out.write(f"{log}\t{cls}\n")
        c = collections.Counter(cls for _, cls in rows)
        safe = c["healthy"] + c["unrelated"]
        print(f"{path}: {len(rows)} rows, safe={safe}, fault={len(rows) - safe}, {dict(c)}")
        return safe, len(rows) - safe

    hs, hf = write(holdout_path, keys[:cut])
    write(dev_path, keys[cut:])
    if bad:
        print(f"skipped {bad} rows without a valid class")
    if hs < 5 or hf < 5:
        print("WARNING: promote-nlp-candidate needs >= 5 safe and >= 5 fault holdout rows")
    return 0


def main(argv):
    if len(argv) >= 4 and argv[0] == "--split":
        return split(argv[1], argv[2], argv[3], opt(argv, "--holdout", 0.5, float), opt(argv, "--seed", 7, int))
    if len(argv) >= 2 and not argv[0].startswith("--"):
        return sample(argv[0], argv[1], opt(argv, "--per-profile", 40, int), opt(argv, "--seed", 7, int))
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
