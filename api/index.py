import csv, io, json, math, os, random, urllib.request
from pathlib import Path
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="TruthLens API")
BENFORD = [math.log10(1 + 1 / d) for d in range(1, 10)]
MISSING = ("na", "n/a", "null", "nan", "none")

class Req(BaseModel):
    csv: str
    target: str = ""
    sensitive: str = ""

def num(v):
    try: return float(v.replace(",", ""))
    except ValueError: return None

def pearson(a, b):
    n = len(a)
    if n < 10: return 0.0
    ma, mb = sum(a) / n, sum(b) / n
    sa = math.sqrt(sum((x - ma) ** 2 for x in a)); sb = math.sqrt(sum((y - mb) ** 2 for y in b))
    return 0.0 if sa == 0 or sb == 0 else sum((x - ma) * (y - mb) for x, y in zip(a, b)) / (sa * sb)

def analyze(text, target="", sensitive=""):
    rows = list(csv.reader(io.StringIO(text.strip())))
    if len(rows) < 21: return {"error": "Need a header row and at least 20 data rows."}
    head = [h.strip() for h in rows[0]]
    body = [r for r in rows[1:50001] if r]
    n = len(body); F = []; cols = []; numeric = {}; raws = {}; best = None
    add = lambda sev, col, msg: F.append({"severity": sev, "column": col, "message": msg})

    dup = n - len({tuple(r) for r in body})
    if dup: add("high" if dup / n > .05 else "medium", "(rows)", f"{dup} duplicate rows ({dup / n:.1%}).")

    for i, h in enumerate(head):
        raw = [(r[i].strip() if i < len(r) else "") for r in body]; raws[h] = raw
        vals = [v for v in raw if v and v.lower() not in MISSING]
        miss = 1 - len(vals) / n
        nums = [num(v) for v in vals]
        isnum = bool(vals) and sum(x is not None for x in nums) >= .9 * len(vals)
        cols.append({"name": h, "type": "numeric" if isnum else "text", "missing": round(miss, 3)})
        if miss > .2: add("high", h, f"{miss:.0%} of values are missing.")
        elif miss > .05: add("medium", h, f"{miss:.0%} of values are missing.")
        if vals and len(set(vals)) == 1: add("low", h, "Constant column - carries no information.")
        if not isnum:
            if len(vals) and len(set(vals)) / len(vals) > .98: add("low", h, "Looks like an identifier - drop it before modelling.")
            continue
        xs = [x for x in nums if x is not None]
        numeric[h] = [num(v) if (v and v.lower() not in MISSING) else None for v in raw]
        s = sorted(xs); q1, q3 = s[len(s) // 4], s[3 * len(s) // 4]; iqr = q3 - q1
        if iqr > 0:
            out = sum(x < q1 - 3 * iqr or x > q3 + 3 * iqr for x in xs)
            if out / len(xs) > .01: add("medium", h, f"{out} extreme outliers ({out / len(xs):.1%}) beyond 3x IQR (min {s[0]:g}, max {s[-1]:g}).")
        pos = [x for x in xs if x > 0]
        if len(pos) >= 200 and len(set(pos)) >= 50 and len(set(pos)) / len(pos) < .98 and max(pos) / min(pos) >= 100:  # Benford's law forensic test
            c = [0] * 9
            for x in pos: c[int(f"{x:e}"[0]) - 1] += 1
            chi = sum((c[d] - len(pos) * BENFORD[d]) ** 2 / (len(pos) * BENFORD[d]) for d in range(9))
            if chi > 20.09: add("high", h, f"Fails Benford's law (chi2={chi:.0f}) - values may be fabricated, capped or manipulated.")
            elif chi > 15.51: add("medium", h, f"Weak Benford deviation (chi2={chi:.0f}) - inspect how this column was produced.")
            if best is None or chi > best[0]: best = (chi, h, [x / len(pos) for x in c])
        big = [x for x in xs if abs(x) >= 100 and x == int(x)]
        if len(big) >= 200 and sum(int(abs(x)) % 5 == 0 for x in big) / len(big) > .5:
            add("medium", h, "Round-number heaping (most values end in 0 or 5) - likely estimated or hand-entered.")

    if target in raws:  # target leakage
        tv = raws[target]; labs = sorted({v for v in tv if v})
        pos_label = next((l for l in labs if l.lower() in ("1", "yes", "true", "y", "approved")), labs[-1] if labs else "")
        if len(labs) == 2: t = [(1.0 if v == pos_label else 0.0) if v else None for v in tv]
        elif target in numeric: t = numeric[target]
        else: t = None
        if t:
            for h, xs in numeric.items():
                if h == target: continue
                p = [(a, b) for a, b in zip(xs, t) if a is not None and b is not None]
                r = pearson([a for a, _ in p], [b for _, b in p])
                if abs(r) > .9: add("high", h, f"Possible target leakage: correlation with '{target}' is {r:.2f}.")
        if sensitive in raws and len(labs) == 2:  # fairness (four-fifths rule)
            g = {}
            for s_, v in zip(raws[sensitive], tv):
                if s_ and v: g.setdefault(s_, []).append(v == pos_label)
            rates = {k: sum(v) / len(v) for k, v in g.items() if len(v) >= 20}
            if len(rates) >= 2 and max(rates.values()) > 0:
                ratio = min(rates.values()) / max(rates.values())
                desc = ", ".join(f"{k}: {v:.0%}" for k, v in rates.items())
                if ratio < .8: add("high", sensitive, f"Bias: disparate impact ratio {ratio:.2f} (<0.80 four-fifths rule). Positive rate '{pos_label}' -> {desc}.")
                elif ratio < .9: add("medium", sensitive, f"Mild group gap: ratio {ratio:.2f}. Positive rate '{pos_label}' -> {desc}.")

    w = {"high": 15, "medium": 7, "low": 3}
    score = max(0, 100 - sum(w[f["severity"]] for f in F))
    F.sort(key=lambda f: -w[f["severity"]])
    out = {"rows": n, "columns": cols, "score": score,
           "grade": "Trustworthy" if score >= 80 else "Questionable" if score >= 55 else "Untrustworthy", "findings": F}
    if best: out["benford"] = {"column": best[1], "observed": [round(x, 4) for x in best[2]], "expected": [round(x, 4) for x in BENFORD]}
    out["summary"] = f"{sum(f['severity'] == 'high' for f in F)} critical and {sum(f['severity'] == 'medium' for f in F)} moderate issues found in {n} rows."
    return out

def llm_summary(res):
    key = os.getenv("GEMINI_API_KEY")
    if not key or not res.get("findings"): return None
    try:
        body = json.dumps({"contents": [{"parts": [{"text": "You are a data auditor. In 3 short sentences, summarise these dataset findings and what to fix first: " + json.dumps(res["findings"][:8])}]}]}).encode()
        r = urllib.request.Request("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" + key, body, {"Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(r, timeout=8))["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception:
        return None

def make_sample():
    random.seed(7); out = ["id,age,gender,city,income,credit_score,loan_amount,approved,approval_code"]
    for i in range(800):
        g = random.choice("MF"); ok = int(random.random() < (.72 if g == "M" else .42))
        age = random.randint(21, 65) if i % 90 else random.randint(150, 250)
        income = round(random.uniform(1000, 150000) / 500) * 500          # fabricated: uniform + rounded
        cs = "" if random.random() < .25 else random.randint(500, 850)      # 25% missing
        loan = int(random.lognormvariate(9, 1.6))                           # natural: passes Benford
        out.append(f"{i},{age},{g},{random.choice(['Pune','Delhi','Chennai','Kavali'])},{income},{cs},{loan},{ok},{ok * 100 + random.randint(0, 3)}")
    return "\n".join(out + out[5:20])                                       # 15 duplicated rows

@app.get("/api/health")
def health(): return {"status": "ok"}

@app.get("/api/sample")
def sample(): return {"csv": make_sample(), "target": "approved", "sensitive": "gender"}

@app.post("/api/analyze")
def run(r: Req):
    res = analyze(r.csv, r.target.strip(), r.sensitive.strip())
    if "error" not in res:
        res["ai_summary"] = llm_summary(res)
    return res

if not os.getenv("VERCEL"):
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=Path(__file__).parent.parent / "public", html=True), name="site")
