"""[S4][K4] Model v2: yerel LLM ile risk skoru.

v1'in hataları (docs/model-v1-hata-analizi.md) ve v2'deki karşılıkları:
  - Skor CVSS'in kopyasıydı        -> rubrik + "CVSS bir girdidir, cevap değildir"
  - Etiket skorla çelişiyordu      -> modelden yalnızca skor istenir, sınıf kodda türetilir
  - Kanıt türünü ayıramıyordu      -> kanıt türü (challenge / Trivy / ZAP) ayrı alan ve kural
  - EPSS yok sayılıyordu           -> EPSS'in nasıl tartılacağı prompt'ta yazılı
  - Biçim hataları sayılmıyordu    -> JSON anahtarları sıkı denetlenir, geçersizler sayılır
  - Türkçe prompt, sınırsız çıktı  -> İngilizce prompt, temperature 0, num_predict 400

Kullanım (repo kökünden, Ollama açıkken):
    python ai/model_v2_local_llm.py                                   # 36 kayıt, 1 kez
    python ai/model_v2_local_llm.py --tekrar-ids V001 V012 V035       # bu kayıtlar 3 kez (tutarlılık)
    python ai/model_v2_local_llm.py --varyant nocvss                  # sayısal CVSS'siz (zaman kalırsa)
    python ai/model_v2_local_llm.py --prompt-goster V001              # prompt'u yazdır, modele gönderme

Çıktı:
    ai/results_v2_llm.csv         (varyant nocvss: ai/results_v2_nocvss_llm.csv)
    ai/model_v2_execution.log
"""

import argparse
import csv
import json
import logging
import os
import re
import statistics
import time

import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5:7b"
OPTIONS = {"temperature": 0, "num_ctx": 4096, "num_predict": 400, "seed": 42}
INVENTORY = "inventory/inventory_v1.0.csv"
MAX_DENEME = 3

# Few-shot örnekleri. Bu kayıtlar değerlendirmeden çıkarılır (v2_degerlendirme.py),
# çünkü model cevabı prompt'tan okuyabilir. Skorlar uzman etiketinin bandında seçildi
# (expert_labels.csv: V023 Yüksek, V006 Orta, V019 Düşük).
FEW_SHOT = [
    ("V023", 7.6, "High band: severe impact if reachable, but this is only a dependency version "
                  "match and the vulnerable code path is not verified; EPSS is moderate."),
    ("V006", 5.8, "Medium band: confirmed in the application, but it needs a logged-in user and "
                  "only exposes another user's basket."),
    ("V019", 2.5, "Low band: version disclosure helps reconnaissance but causes no demonstrated loss."),
]

AV = {"N": "network", "A": "adjacent network", "L": "local", "P": "physical"}
AC = {"L": "low", "H": "high"}
PR = {"N": "none", "L": "low (normal user)", "H": "high (administrator)"}
UI = {"N": "not required", "R": "required (victim must act)"}
SC = {"U": "unchanged", "C": "changed (impact beyond the vulnerable component)"}
CIA = {"H": "high", "L": "low", "N": "none"}

GRANTS = {
    "admin_session": "gives an administrator session",
    "admin_credentials": "yields administrator credentials",
    "forged_identity": "allows forging an identity token",
    "stolen_session": "can steal another user's session",
    "password_hashes": "exposes stored password hashes",
    "trusted_ip": "lets the attacker spoof a trusted client IP",
}
REQUIRES = {"password_hashes": "requires password hashes obtained through another vulnerability"}


def vektor_sozle(vector):
    parca = dict(p.split(":", 1) for p in (vector or "").split("/")[1:] if ":" in p)
    if not parca:
        return "unknown"
    return (f"attack vector {AV.get(parca.get('AV'), '?')}; attack complexity {AC.get(parca.get('AC'), '?')}; "
            f"privileges required {PR.get(parca.get('PR'), '?')}; user interaction {UI.get(parca.get('UI'), '?')}; "
            f"scope {SC.get(parca.get('S'), '?')}; impact: confidentiality {CIA.get(parca.get('C'), '?')}, "
            f"integrity {CIA.get(parca.get('I'), '?')}, availability {CIA.get(parca.get('A'), '?')}")


def kanit(notes):
    """notes alanından kanıt türünü, tarayıcının önem derecesini ve belirsizlik işaretini çıkarır."""
    n = (notes or "").strip()
    belirsiz = n.upper().startswith("[EMIN DEGIL]")
    n = re.sub(r"^\[EMIN DEGIL\]\s*", "", n, flags=re.I)
    # Uygulamanın yeni kayıtlara eklediği işaret (envanterde olmayan, otomatik oluşturulan satır)
    n = re.sub(r"^\[OTOMATIK\]\s*", "", n, flags=re.I)
    if n.startswith("challenges.json"):
        tur = ("Confirmed in this application: Juice Shop has a challenge for this weakness, "
               "so it is known to be exploitable here")
    elif n.startswith("trivy.json"):
        tur = ("Dependency scan (Trivy): a vulnerable package version is installed; whether the "
               "application actually reaches the vulnerable code is NOT verified")
    elif n.startswith("zap_baseline.json"):
        tur = "Passive web scanner (ZAP baseline) observation; no exploit was demonstrated"
    else:
        tur = "Unknown source"
    m = re.match(r"(?:trivy|zap_baseline)\.json:\s*(CRITICAL|HIGH|MEDIUM|LOW|High|Medium|Low)", n)
    siddet = m.group(1).upper() if m else "none"
    return tur, siddet, belirsiz, n


def bulgu_metni(r, cvss_var=True):
    tur, siddet, belirsiz, not_ = kanit(r.get("notes"))
    epss = (r.get("epss_score") or "").strip()
    epss = epss if epss and epss.lower() not in ("bilinmiyor", "nan") else "not available (no CVE)"
    grants = (r.get("grants_capability") or "none").strip().lower()
    requires = (r.get("requires_capability") or "none").strip().lower()
    satirlar = [
        f"- Name: {r['name']}",
        f"- Component: {r['component']}",
        f"- CWE: {r['cwe_id']}",
        f"- Evidence: {tur}",
        f"- Scanner's own severity: {siddet}",
    ]
    if cvss_var:
        satirlar.append(f"- CVSS v3.1 base score: {r['cvss_score']}")
    satirlar += [
        f"- CVSS vector in words: {vektor_sozle(r.get('cvss_vector'))}",
        f"- EPSS: {epss}",
        f"- Entry point: {r.get('entry_point') or 'unknown'}",
        f"- Asset criticality (1-5): {r.get('asset_criticality')}",
    ]
    if grants != "none":
        satirlar.append(f"- If exploited, it {GRANTS.get(grants, grants)}")
    if requires != "none":
        satirlar.append(f"- Precondition: {REQUIRES.get(requires, requires)}")
    if belirsiz:
        satirlar.append("- Inventory marks this record as UNCERTAIN (some values are assumptions)")
    satirlar.append(f"- Analyst note (Turkish): {not_}")
    return "\n".join(satirlar)


def prompt_olustur(r, envanter, cvss_var=True):
    cvss_kural = ("The CVSS base score describes the vulnerability in general. It is an input, not the "
                  "answer: do not copy it. Decide the band with the rubric first, then place the finding "
                  "inside the band." if cvss_var else
                  "Decide the band with the rubric first, then place the finding inside the band.")
    dep_kural = ("even if its CVSS score is 9 or more" if cvss_var else "even if its impact is high")
    ayir = ("CVSS, EPSS and asset criticality" if cvss_var else "the vector, EPSS and asset criticality")
    ornekler = "\n\n".join(
        f"Example finding:\n{bulgu_metni(envanter[vid], cvss_var)}\nAnswer: "
        f"{json.dumps({'risk_score': skor, 'reason': gerekce})}"
        for vid, skor, gerekce in FEW_SHOT)
    return f"""You are a security analyst prioritizing vulnerabilities found in one OWASP Juice Shop instance.
Score how urgently each finding should be fixed in THIS application, from 0.0 to 10.0 with one decimal.
{cvss_kural}

Rubric:
- 9.0-10.0 Critical: exploitation is confirmed in this application, needs no authentication and no user
  interaction, and gives administrator access, full system compromise or large-scale exposure of sensitive data.
- 7.0-8.9 High: serious impact, but one factor keeps it below Critical: it is a dependency finding whose
  vulnerable code path is not verified; or it needs authentication, high attack complexity or user interaction;
  or the confirmed impact is limited to reading data.
- 4.0-6.9 Medium: impact limited to one account, one user's browser, one basket or one function; or it needs
  meaningful user interaction or preconditions; or the evidence is contradictory or uncertain.
- 0.0-3.9 Low: information disclosure or missing defense-in-depth (security headers, version banners,
  verbose errors) with no demonstrated loss.

How to weigh the evidence:
- Confirmed in this application > dependency version match > passive scanner observation.
- A dependency finding with unverified reachability normally stays in the High band or below, {dep_kural}.
- If the scanner's own severity is lower than the impact suggests, or the record is marked uncertain, move down.
- EPSS is the probability of exploitation in the wild in the next 30 days. Above 0.1 is high and moves the
  score up within its band; below 0.01 is low.
- Within a band, use {ayir} to separate findings.

{ornekler}

Finding to score:
{bulgu_metni(r, cvss_var)}

Return only JSON with exactly these two keys:
{{"risk_score": <number from 0.0 to 10.0, one decimal>, "reason": "<at most 40 words: the rubric band and the deciding factor>"}}"""


def sinif(skor):
    """Sınıf skordan türetilir (CVSS v3.1 bantları); modele ayrıca sorulmaz."""
    if skor >= 9.0:
        return "Kritik"
    if skor >= 7.0:
        return "Yüksek"
    if skor >= 4.0:
        return "Orta"
    return "Düşük"


def dogrula(icerik):
    """Yanıtı sıkı denetler: tam olarak risk_score ve reason anahtarları, skor 0-10 arası sayı."""
    veri = json.loads(icerik)
    if set(veri) != {"risk_score", "reason"}:
        raise ValueError(f"anahtarlar hatalı: {sorted(veri)}")
    skor = veri["risk_score"]
    if isinstance(skor, bool) or not isinstance(skor, (int, float)) or not 0 <= skor <= 10:
        raise ValueError(f"skor geçersiz: {skor!r}")
    if not isinstance(veri["reason"], str) or not veri["reason"].strip():
        raise ValueError("reason boş")
    return round(float(skor), 1), veri["reason"].strip()


def sor(prompt, vid, model):
    """Bir skor alır. Dönüş: (skor, gerekçe, geçersiz_deneme_sayısı, prompt_token)."""
    gecersiz, prompt_token = 0, None
    for deneme in range(1, MAX_DENEME + 1):
        try:
            yanit = requests.post(OLLAMA_URL, timeout=180, json={
                "model": model, "prompt": prompt, "stream": False, "format": "json", "options": OPTIONS})
            yanit.raise_for_status()
            govde = yanit.json()
            prompt_token = govde.get("prompt_eval_count", prompt_token)
            skor, gerekce = dogrula(govde.get("response", ""))
            return skor, gerekce, gecersiz, prompt_token
        except Exception as e:
            gecersiz += 1
            logging.warning(f"[{vid}] geçersiz yanıt (deneme {deneme}/{MAX_DENEME}): {e}")
            time.sleep(1)
    return None, None, gecersiz, prompt_token


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--varyant", choices=["v2", "nocvss"], default="v2")
    ap.add_argument("--model", default=MODEL_NAME)
    ap.add_argument("--tekrar", type=int, default=3, help="--tekrar-ids kayıtları için tekrar sayısı")
    ap.add_argument("--tekrar-ids", nargs="*", default=[], help="Tutarlılık için birden çok kez çalıştırılacak kayıtlar")
    ap.add_argument("--prompt-goster", metavar="VULN_ID")
    args = ap.parse_args()

    cvss_var = args.varyant == "v2"
    cikti = "ai/results_v2_llm.csv" if cvss_var else "ai/results_v2_nocvss_llm.csv"
    os.makedirs("ai", exist_ok=True)
    logging.basicConfig(filename="ai/model_v2_execution.log", level=logging.INFO, encoding="utf-8",
                        format="%(asctime)s - %(levelname)s - %(message)s")

    with open(INVENTORY, encoding="utf-8") as f:
        envanter = {r["vuln_id"]: r for r in csv.DictReader(f)}

    if args.prompt_goster:
        print(prompt_olustur(envanter[args.prompt_goster], envanter, cvss_var))
        return

    few_ids = {vid for vid, _, _ in FEW_SHOT}
    logging.info(f"Başlangıç: model={args.model} varyant={args.varyant} options={OPTIONS}")
    sonuclar, max_token, toplam_gecersiz, basarisiz = [], 0, 0, []
    t0 = time.time()
    for i, (vid, r) in enumerate(envanter.items(), start=1):
        prompt = prompt_olustur(r, envanter, cvss_var)
        n = args.tekrar if vid in args.tekrar_ids else 1
        skorlar, gerekceler = [], []
        for _ in range(n):
            skor, gerekce, gecersiz, token = sor(prompt, vid, args.model)
            toplam_gecersiz += gecersiz
            max_token = max(max_token, token or 0)
            if skor is not None:
                skorlar.append(skor)
                gerekceler.append(gerekce)
        if not skorlar:
            basarisiz.append(vid)
            print(f"[{i}/{len(envanter)}] {vid}: BAŞARISIZ")
            continue
        skor = round(statistics.median(skorlar), 1)
        sonuclar.append({
            "vuln_id": vid,
            "risk_score_llm": skor,
            "risk_label_llm": sinif(skor),
            "llm_reason": gerekceler[0],
            "score_std": round(statistics.pstdev(skorlar), 3) if len(skorlar) > 1 else "",
            "tekrar_skorlari": " ".join(str(s) for s in skorlar) if n > 1 else "",
            "few_shot": vid in few_ids,
        })
        print(f"[{i}/{len(envanter)}] {vid}: {skorlar} -> {sinif(skor)}")

    with open(cikti, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(sonuclar[0].keys()))
        w.writeheader()
        w.writerows(sonuclar)

    print(f"\nModel: {args.model}, varyant: {args.varyant}, süre: {time.time() - t0:.0f} sn")
    print(f"Başarılı: {len(sonuclar)}/{len(envanter)}, başarısız: {basarisiz or 'yok'}, geçersiz deneme: {toplam_gecersiz}")
    print(f"En uzun prompt: {max_token} token (num_ctx {OPTIONS['num_ctx']})")
    if max_token > OPTIONS["num_ctx"] - OPTIONS["num_predict"]:
        print("UYARI: prompt num_ctx'e çok yakın, Ollama kırpıyor olabilir. num_ctx'i artır.")
    print(f"Yazıldı: {cikti}")
    logging.info(f"Bitti: başarılı={len(sonuclar)} geçersiz_deneme={toplam_gecersiz} max_prompt_token={max_token}")


if __name__ == "__main__":
    main()
