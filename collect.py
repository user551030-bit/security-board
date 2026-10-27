"""セキュリティ情報の収集と Web ページ生成。

各情報源（RSS・JSON）を取得し、CVE 番号と製品名で同じ話題をまとめ、
重要度をつけて site/index.html を作る。標準ライブラリだけで動く。

使い方: python collect.py [--days 14]
"""
import argparse
import datetime as dt
import email.utils
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent
JST = dt.timezone(dt.timedelta(hours=9))
UA = "Mozilla/5.0 (security-feed; personal use)"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
RSS1 = "{http://purl.org/rss/1.0/}"
DC = "{http://purl.org/dc/elements/1.1/}"

# 重要度: 3=緊急 2=注意 1=参考
SOURCES = {
    "ipa": {"name": "IPA", "url": "https://www.ipa.go.jp/security/rss/alert.rdf",
            "home": "https://www.ipa.go.jp/security/security-alert/index.html"},
    "jpcert": {"name": "JPCERT/CC", "url": "https://www.jpcert.or.jp/rss/jpcert.rdf",
               "home": "https://www.jpcert.or.jp/"},
    "jvn": {"name": "JVN", "url": "https://jvn.jp/rss/jvn.rdf", "home": "https://jvn.jp/"},
    "kev": {"name": "CISA KEV",
            "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "home": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
    "msrc": {"name": "Microsoft", "url": "https://api.msrc.microsoft.com/update-guide/rss",
             "home": "https://msrc.microsoft.com/update-guide/"},
    "snext": {"name": "Security NEXT", "url": "https://www.security-next.com/feed",
              "home": "https://www.security-next.com/"},
    "piyolog": {"name": "piyolog", "url": "https://piyolog.hatenadiary.jp/rss",
                "home": "https://piyolog.hatenadiary.jp/"},
}
# 代表タイトルに使う優先順（日本語の公的情報を優先）
TITLE_ORDER = ["ipa", "jpcert", "jvn", "piyolog", "snext", "kev", "msrc"]

# 英語の脆弱性の種類 → 日本語（長いものから順に当てる）
VULN_TYPES = [
    ("Authentication Bypass by Spoofing", "なりすましによる認証回避"),
    ("Files or Directories Accessible to External Parties", "外部からファイルにアクセスできる"),
    ("External Control of File Name or Path", "ファイル名・パスの外部操作"),
    ("Improper Neutralization of Encoded URI Schemes in a Web Page", "Web ページの URI スキーム処理の不備"),
    ("Server-Side Request Forgery (SSRF)", "SSRF（サーバーを踏み台にした不正リクエスト）"),
    ("Deserialization of Untrusted Data", "信頼できないデータの復元（デシリアライズ）"),
    ("Missing Authentication for Critical Function", "重要機能の認証漏れ"),
    ("Uncontrolled Search Path Element", "読み込み先パスの制御不備"),
    ("Security Feature Bypass", "セキュリティ機能の回避"),
    ("Remote Code Execution", "遠隔からのコード実行"),
    ("Elevation of Privilege", "権限昇格"),
    ("Privilege Escalation", "権限昇格"),
    ("Information Disclosure", "情報漏えい"),
    ("Denial of Service", "サービス妨害"),
    ("Relative Path Traversal", "パストラバーサル（不正なファイル参照）"),
    ("Path Traversal", "パストラバーサル（不正なファイル参照）"),
    ("OS Command Injection", "OS コマンドインジェクション"),
    ("Command Injection", "コマンドインジェクション"),
    ("Code Injection", "コードインジェクション"),
    ("SQL Injection", "SQL インジェクション"),
    ("Cross-Site Scripting", "クロスサイトスクリプティング"),
    ("Cross-site Scripting", "クロスサイトスクリプティング"),
    ("Heap-based Buffer Overflow", "ヒープバッファオーバーフロー"),
    ("Stack-based Buffer Overflow", "スタックバッファオーバーフロー"),
    ("Buffer Overflow", "バッファオーバーフロー"),
    ("Out-of-Bounds Write", "境界外書き込み"),
    ("Out-of-bounds Write", "境界外書き込み"),
    ("Out-of-Bounds Read", "境界外読み取り"),
    ("Out-of-bounds Read", "境界外読み取り"),
    ("Use-After-Free", "解放済みメモリの使用"),
    ("Use After Free", "解放済みメモリの使用"),
    ("Memory Corruption", "メモリ破損"),
    ("Type Confusion", "型の取り違え"),
    ("Improper Authentication", "認証の不備"),
    ("Missing Authorization", "権限確認の漏れ"),
    ("Incorrect Authorization", "権限確認の誤り"),
    ("Improper Access Control", "アクセス制御の不備"),
    ("Improper Input Validation", "入力チェックの不備"),
    ("Hard-coded Credentials", "埋め込まれたパスワード"),
    ("Spoofing", "なりすまし"),
    ("Tampering", "改ざん"),
]
# 製品名での突き合わせに使わない、ありふれた名前
GENERIC_PRODUCTS = {"multiple products", "windows", "media server", "software center",
                    "remote support", "office", "server", "chrome"}


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def parse_date(text):
    if not text:
        return None
    text = text.strip()
    try:
        d = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError):
        d = None
    if d is None:
        t = text.replace("Z", "+00:00")
        if re.match(r".*T\d\d:\d\d[+-]", t):  # 秒がない形式（JPCERT）
            t = re.sub(r"T(\d\d:\d\d)([+-])", r"T\1:00\2", t)
        try:
            d = dt.datetime.fromisoformat(t)
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=JST)
    return d.astimezone(JST)


def ja_vuln_type(name):
    for en, ja in VULN_TYPES:
        if en.lower() in name.lower():
            return ja
    return None


def item(source, title, url, date, kind, level, text="", **extra):
    cves = sorted(set(CVE_RE.findall(f"{title} {text}")))
    return {"source": source, "title": title.strip(), "url": url, "date": date.isoformat(),
            "kind": kind, "level": level, "cves": cves, "text": text.strip(), **extra}


# ---- 情報源ごとの取り込み ----

def src_ipa(raw, since):
    out, seen = [], set()
    for it in ET.fromstring(raw).iter(RSS1 + "item"):
        url = it.findtext(RSS1 + "link")
        d = parse_date(it.findtext(DC + "date"))
        if not d or d < since or url in seen:  # 新しい順。同じページの更新は最新だけ残す
            continue
        seen.add(url)
        out.append(item("ipa", it.findtext(RSS1 + "title"), url, d, "vuln", 3))
    return out


def src_jpcert(raw, since):
    out = []
    for it in ET.fromstring(raw).iter(RSS1 + "item"):
        url = it.findtext(RSS1 + "link")
        d = parse_date(it.findtext(DC + "date"))
        if not d or d < since:
            continue
        title = it.findtext(RSS1 + "title")
        if "/at/" in url:
            title = re.sub(r"^注意喚起:\s*", "", title)
            kind = "vuln" if "脆弱性" in title or "更新プログラム" in title else "incident"
            out.append(item("jpcert", title, url, d, kind, 3, label="注意喚起"))
        else:
            title = re.sub(r"^Weekly Report:\s*", "", title)
            kind = "vuln" if "脆弱性" in title else "news"
            out.append(item("jpcert", title, url, d, kind, 2 if kind == "vuln" else 1,
                            label="Weekly Report"))
    return out


def src_jvn(raw, since):
    out = []
    for it in ET.fromstring(raw).iter(RSS1 + "item"):
        d = parse_date(it.findtext(DC + "date"))
        if not d or d < since:
            continue
        ident = it.findtext(DC + "identifier") or ""
        out.append(item("jvn", it.findtext(RSS1 + "title"), it.findtext(RSS1 + "link"), d,
                        "vuln", 2, it.findtext(RSS1 + "description") or "",
                        label="国内製品" if ident.startswith("JVN#") else "海外製品"))
    return out


def src_kev(raw, since):
    out = []
    for v in json.loads(raw)["vulnerabilities"]:
        d = parse_date(v["dateAdded"] + "T09:00:00-04:00")
        if d < since:
            continue
        product = v["product"].replace("Multiple Products", "複数製品")
        vtype = ja_vuln_type(v["vulnerabilityName"])
        title = f"{v['vendorProject']} {product} の脆弱性" + (f"（{vtype}）" if vtype else "")
        out.append(item("kev", title, f"https://nvd.nist.gov/vuln/detail/{v['cveID']}", d, "vuln", 3,
                        v["cveID"], exploited=True, label=v["cveID"], kev_due=v["dueDate"],
                        ransomware=v["knownRansomwareCampaignUse"] == "Known",
                        en=v["vulnerabilityName"], vendor=v["vendorProject"], product=v["product"]))
    return out


def src_msrc(raw, since):
    """新規公開分だけを返す（改訂や Chrome 由来の転載は除く）。"""
    out = []
    for it in ET.fromstring(raw).iter("item"):
        d = parse_date(it.findtext("pubDate"))
        desc = it.findtext("description") or ""
        if (not d or d < since or not it.get("Revision", "").startswith("1.0")
                or "assigned by Chrome" in desc or it.findtext("category") != "CVE"):
            continue
        en = it.findtext("title")
        cve = it.findtext("guid")
        name = en.replace(cve, "").replace("Vulnerability", "").strip()
        vtype = ja_vuln_type(name)
        target = name
        if vtype:
            for e, j in VULN_TYPES:
                if j == vtype:
                    target = re.sub(re.escape(e), "", target, flags=re.I).strip()
        out.append(item("msrc", f"{target} の脆弱性" + (f"（{vtype}）" if vtype else ""), it.findtext("link"), d, "vuln", 2,
                        cve, en=en, vtype=vtype or "その他"))
    return out


def src_snext(raw, since):
    out = []
    for it in ET.fromstring(raw).iter("item"):
        d = parse_date(it.findtext("pubDate"))
        if not d or d < since:
            continue
        cats = [c.text for c in it.findall("category")]
        title = it.findtext("title")
        if "脆弱性" in cats:
            kind, level = "vuln", 1
        elif any("事件" in c or "漏洩" in c or "不正アクセス" in c for c in cats):
            kind, level = "incident", 1
        else:
            kind, level = "news", 1
        out.append(item("snext", title, it.findtext("link"), d, kind, level,
                        it.findtext("description") or ""))
    return out


def src_piyolog(raw, since):
    out = []
    for it in ET.fromstring(raw).iter("item"):
        d = parse_date(it.findtext("pubDate"))
        if not d or d < since:
            continue
        title = it.findtext("title")
        kind = "vuln" if ("脆弱性" in title or CVE_RE.search(title)) else "incident"
        out.append(item("piyolog", title, it.findtext("link"), d, kind, 2,
                        label="まとめ記事"))
    return out


PARSERS = {"ipa": src_ipa, "jpcert": src_jpcert, "jvn": src_jvn, "kev": src_kev,
           "msrc": src_msrc, "snext": src_snext, "piyolog": src_piyolog}


# ---- まとめ（同じ話題を 1 件に） ----

def norm(s):
    return re.sub(r"[\s\-–—_・「」『』]+", "", s).lower()


def cluster(items):
    parent = list(range(len(items)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a, b):
        parent[find(a)] = find(b)

    by_key = {}
    for i, it in enumerate(items):
        for c in it["cves"]:
            by_key.setdefault(c, []).append(i)
        if it["source"] in ("ipa", "jpcert", "jvn", "snext", "piyolog"):
            by_key.setdefault("url:" + it["url"], []).append(i)
    for idx in by_key.values():
        for j in idx[1:]:
            union(idx[0], j)

    # 公的機関（IPA・JPCERT・JVN）のタイトルを基準に、名前でも突き合わせる
    official = [(i, norm(it["title"]), it["date"][:10]) for i, it in enumerate(items)
                if it["source"] in ("ipa", "jpcert", "jvn")]

    def near(a, b, days=7):
        return abs((dt.date.fromisoformat(a) - dt.date.fromisoformat(b)).days) <= days

    for i, it in enumerate(items):
        # CISA KEV の製品名が公的機関のタイトルに出てくる（前後 7 日以内）
        if it["source"] == "kev":
            keys = [norm(f"{it['vendor']} {it['product']}")]
            if norm(it["product"]) not in {norm(g) for g in GENERIC_PRODUCTS} and len(it["product"]) >= 6:
                keys.append(norm(it["product"]))
            for j, t, d in official:
                if near(it["date"][:10], d) and any(k and k in t for k in keys):
                    union(i, j)
        # ニュース記事の「」で囲まれた脆弱性の通称（PHP2Shell など）が公的機関のタイトルにある
        if it["source"] in ("snext", "piyolog"):
            for name in re.findall(r"「([^」]{8,})」", it["title"]):
                if re.fullmatch(r"[A-Za-z0-9.\- ]+", name):
                    for j, t, d in official:
                        if norm(name) in t:
                            union(i, j)

    groups = {}
    for i, it in enumerate(items):
        groups.setdefault(find(i), []).append(it)
    return list(groups.values())


def build_topics(groups):
    topics, msrc_rest = [], []
    for g in groups:
        if all(x["source"] == "msrc" for x in g):
            msrc_rest.extend(g)
            continue
        g.sort(key=lambda x: (TITLE_ORDER.index(x["source"]), x["date"]))
        head = g[0]
        exploited = any(x.get("exploited") for x in g) or any("悪用" in x["title"] for x in g)
        level = max(x["level"] for x in g)
        if exploited:
            level = 3
        kinds = {x["kind"] for x in g}
        kind = "vuln" if "vuln" in kinds else ("incident" if "incident" in kinds else "news")
        kev = [x for x in g if x["source"] == "kev"]
        topics.append({
            "title": head["title"],
            "url": head["url"],
            "date": max(x["date"] for x in g),
            "level": level,
            "kind": kind,
            "exploited": exploited,
            "kev_due": min((x["kev_due"] for x in kev), default=None),
            "ransomware": any(x.get("ransomware") for x in kev),
            "cves": sorted({c for x in g for c in x["cves"]}),
            "en": [x["en"] for x in kev],
            # 公開ページに載せる説明文は JVN（公的機関）のものだけ。ニュースサイトの本文は転載しない
            "summary": next((x["text"] for x in g if x["source"] == "jvn" and x["text"]), ""),
            "sources": [{"id": x["source"], "name": SOURCES[x["source"]]["name"],
                         "label": x.get("label", ""), "title": x["title"], "url": x["url"],
                         "date": x["date"]} for x in sorted(g, key=lambda x: x["date"], reverse=True)],
        })
    if msrc_rest:
        topics.append(msrc_digest(msrc_rest))
    topics.sort(key=lambda t: t["date"], reverse=True)
    return topics


def msrc_digest(items):
    counts = {}
    for x in items:
        counts[x["vtype"]] = counts.get(x["vtype"], 0) + 1
    rce = [x for x in items if x["vtype"] == "遠隔からのコード実行"]
    breakdown = "、".join(f"{k} {v} 件" for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:5])
    return {
        "title": f"Microsoft 製品の脆弱性 {len(items)} 件が新たに公開",
        "url": SOURCES["msrc"]["home"],
        "date": max(x["date"] for x in items),
        "level": 2, "kind": "vuln", "exploited": False, "kev_due": None, "ransomware": False,
        "cves": [], "en": [],
        "summary": f"内訳: {breakdown}。Windows Update などで更新を適用してください。",
        "digest": [{"title": x["title"], "url": x["url"], "cve": x["cves"][0]}
                   for x in sorted(rce, key=lambda x: x["date"], reverse=True)[:30]],
        "sources": [{"id": "msrc", "name": "Microsoft", "label": "まとめ", "title": "Security Update Guide",
                     "url": SOURCES["msrc"]["home"], "date": max(x["date"] for x in items)}],
    }


def add_epss(topics, status):
    cves = sorted({c for t in topics for c in t["cves"]})
    scores = {}
    try:
        for i in range(0, len(cves), 50):
            raw = fetch("https://api.first.org/data/v1/epss?cve=" + ",".join(cves[i:i + 50]))
            for row in json.loads(raw)["data"]:
                scores[row["cve"]] = float(row["epss"])
        status.append({"name": "FIRST EPSS", "ok": True, "count": len(scores),
                       "home": "https://www.first.org/epss/"})
    except Exception as e:  # 取れなくてもページは作る
        status.append({"name": "FIRST EPSS", "ok": False, "error": str(e)[:120],
                       "home": "https://www.first.org/epss/"})
    for t in topics:
        vals = [scores[c] for c in t["cves"] if c in scores]
        t["epss"] = max(vals) if vals else None


def main():
    sys.stderr.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=14)
    args = ap.parse_args()
    now = dt.datetime.now(JST)
    since = now - dt.timedelta(days=args.days)

    items, status = [], []
    for sid, src in SOURCES.items():
        try:
            got = PARSERS[sid](fetch(src["url"]), since)
            items.extend(got)
            status.append({"name": src["name"], "ok": True, "count": len(got), "home": src["home"]})
        except Exception as e:
            status.append({"name": src["name"], "ok": False, "error": str(e)[:120], "home": src["home"]})
        print(f"{src['name']}: {status[-1].get('count', 'NG')}", file=sys.stderr)

    topics = build_topics(cluster(items))
    add_epss(topics, status)
    data = {"generated": now.isoformat(), "days": args.days, "topics": topics, "status": status}

    (ROOT / "site").mkdir(exist_ok=True)
    (ROOT / "site" / "data.json").write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    html = (ROOT / "template.html").read_text(encoding="utf-8")
    html = html.replace("/*__DATA__*/null", json.dumps(data, ensure_ascii=False).replace("</", "<\\/"))
    (ROOT / "site" / "index.html").write_text(html, encoding="utf-8")
    print(f"話題 {len(topics)} 件 → site/index.html", file=sys.stderr)


if __name__ == "__main__":
    main()
