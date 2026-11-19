"""[S3][K4] Model v1 tutarlılık testi.

Her kaydı v1'in kendi prompt'u ve ayarlarıyla (model_v1_local_llm.py) 3 kez
çalıştırır; skorun ve etiketin ne kadar değiştiğini ölçer. v1 kodu değiştirilmez,
yalnızca içe aktarılır.

Kullanım (repo kökünden, Ollama açıkken):
    python ai/v1_tutarlilik.py                       # 36 kayıt x 3 tekrar
    python ai/v1_tutarlilik.py --ids V001 V012 V035  # yalnızca seçilen kayıtlar
    python ai/v1_tutarlilik.py --tekrar 5

Çıktı:
    ai/v1_tutarlilik.csv
"""

import argparse
import csv
import importlib.util
import os
import statistics
import time

import pandas as pd

AI_DIR = os.path.dirname(os.path.abspath(__file__))
INVENTORY = "inventory/inventory_v1.0.csv"
RESULTS_V1 = "ai/results_v1_llm.csv"
OUT = "ai/v1_tutarlilik.csv"

# phi3:mini ile phi3:3.8b aynı modelin iki etiketi (Ollama ID 4f2222927938).
# Bu makinede yalnızca phi3:3.8b etiketi yüklü olduğu için o kullanılır.
MODEL = "phi3:3.8b"


def v1_modulu():
    spec = importlib.util.spec_from_file_location("model_v1", os.path.join(AI_DIR, "model_v1_local_llm.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tekrar", type=int, default=3)
    ap.add_argument("--ids", nargs="*")
    ap.add_argument("--model", default=MODEL)
    args = ap.parse_args()

    v1 = v1_modulu()
    v1.MODEL_NAME = args.model  # prompt, sıcaklık (0.1) ve num_ctx v1 ile aynı kalır

    inv = pd.read_csv(INVENTORY)
    if args.ids:
        inv = inv[inv["vuln_id"].isin(args.ids)]
    onceki = {}
    if os.path.exists(RESULTS_V1):
        onceki = pd.read_csv(RESULTS_V1).set_index("vuln_id")["risk_score_llm"].to_dict()

    satirlar, toplam_sure = [], 0.0
    for i, (_, row) in enumerate(inv.iterrows(), start=1):
        vid = row["vuln_id"]
        prompt = v1.PROMPT_TEMPLATE.format(
            vuln_id=vid, cve_id=row.get("cve_id", "Bilinmiyor"), name=row.get("name", "Bilinmiyor"),
            component=row.get("component", "Bilinmiyor"), cwe_id=row.get("cwe_id", "Bilinmiyor"),
            cvss_score=row.get("cvss_score", 0.0), cvss_vector=row.get("cvss_vector", "Bilinmiyor"),
            epss_score=row.get("epss_score", 0.0), exposure=row.get("exposure", "Bilinmiyor"),
            auth_required=row.get("auth_required", "Bilinmiyor"),
            attack_complexity=row.get("attack_complexity", "Bilinmiyor"),
            asset_criticality=row.get("asset_criticality", "Bilinmiyor"), notes=row.get("notes", "Yok"))

        skorlar, etiketler, gecersiz = [], [], 0
        for _ in range(args.tekrar):
            t0 = time.time()
            r = v1.query_local_llm(prompt, vid)
            toplam_sure += time.time() - t0
            if r is None:
                gecersiz += 1
                continue
            skorlar.append(r["risk_score_llm"])
            etiketler.append(r["risk_label_llm"])

        std = round(statistics.pstdev(skorlar), 3) if len(skorlar) > 1 else ""
        satir = {
            "vuln_id": vid,
            "cvss": row.get("cvss_score"),
            "v1_kayitli_skor": onceki.get(vid, ""),
            **{f"skor_{k+1}": (skorlar[k] if k < len(skorlar) else "") for k in range(args.tekrar)},
            **{f"etiket_{k+1}": (etiketler[k] if k < len(etiketler) else "") for k in range(args.tekrar)},
            "skor_std": std,
            "skor_araligi": round(max(skorlar) - min(skorlar), 3) if skorlar else "",
            "etiket_degisti": len(set(etiketler)) > 1,
            "gecersiz": gecersiz,
        }
        satirlar.append(satir)
        print(f"[{i}/{len(inv)}] {vid}: skorlar {skorlar} etiketler {etiketler} geçersiz {gecersiz}")

    with open(OUT, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(satirlar[0].keys()))
        w.writeheader()
        w.writerows(satirlar)

    stdler = [s["skor_std"] for s in satirlar if s["skor_std"] != ""]
    cagri = len(satirlar) * args.tekrar
    print("\n== Özet ==")
    print(f"Model: {args.model}, kayıt: {len(satirlar)}, tekrar: {args.tekrar}, çağrı: {cagri}")
    print(f"Ortalama süre/çağrı: {toplam_sure / cagri:.1f} sn")
    if stdler:
        print(f"Skor std ortalaması: {statistics.mean(stdler):.3f}, en yüksek: {max(stdler):.3f}")
        print(f"Skoru hiç değişmeyen kayıt: {sum(s == 0 for s in stdler)}/{len(stdler)}")
    print(f"Etiketi değişen kayıt: {[s['vuln_id'] for s in satirlar if s['etiket_degisti']]}")
    print(f"Geçersiz yanıt (toplam): {sum(s['gecersiz'] for s in satirlar)}")
    print(f"Yazıldı: {OUT}")


if __name__ == "__main__":
    main()
