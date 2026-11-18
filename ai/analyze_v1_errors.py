import os
import statistics
import pandas as pd
from model_v1_local_llm import PROMPT_TEMPLATE, query_local_llm

INVENTORY_PATH = "inventory/inventory_v1.0.csv"
RESULTS_PATH = "ai/results_v1_llm.csv"
EXPERT_PATH = "ai/expert_labels.csv"
OUTPUT_MD_PATH = "docs/model-v1-hata-analizi.md"

# Tutarlılık testi için farklı kategorilerden seçilen 5 temsili kayıt
CONSISTENCY_SAMPLES = ["V001", "V003", "V018", "V022", "V035"]
REPEAT_COUNT = 3


def run_consistency_test(inv_df):
    print(f"\nTutarlılık testi başlatılıyor ({len(CONSISTENCY_SAMPLES)} kayıt x {REPEAT_COUNT} tekrar)...")
    consistency_rows = []

    for vuln_id in CONSISTENCY_SAMPLES:
        row_match = inv_df[inv_df["vuln_id"] == vuln_id]
        if row_match.empty:
            continue
        row = row_match.iloc[0]

        prompt = PROMPT_TEMPLATE.format(
            vuln_id=vuln_id,
            cve_id=row.get("cve_id", "Bilinmiyor"),
            name=row.get("name", "Bilinmiyor"),
            component=row.get("component", "Bilinmiyor"),
            cwe_id=row.get("cwe_id", "Bilinmiyor"),
            cvss_score=row.get("cvss_score", 0.0),
            cvss_vector=row.get("cvss_vector", "Bilinmiyor"),
            epss_score=row.get("epss_score", 0.0),
            exposure=row.get("exposure", "Bilinmiyor"),
            auth_required=row.get("auth_required", "Bilinmiyor"),
            attack_complexity=row.get("attack_complexity", "Bilinmiyor"),
            asset_criticality=row.get("asset_criticality", "Bilinmiyor"),
            notes=row.get("notes", "Yok"),
        )

        scores = []
        labels = []
        for run_idx in range(1, REPEAT_COUNT + 1):
            resp = query_local_llm(prompt, f"{vuln_id}-run{run_idx}")
            if resp:
                scores.append(resp["risk_score_llm"])
                labels.append(resp["risk_label_llm"])
            else:
                scores.append(None)
                labels.append("HATA")

        valid_scores = [s for s in scores if s is not None]
        if len(valid_scores) >= 2:
            score_diff = round(max(valid_scores) - min(valid_scores), 4)
            score_std = round(statistics.stdev(valid_scores), 4)
        elif len(valid_scores) == 1:
            score_diff = 0.0
            score_std = 0.0
        else:
            score_diff = None
            score_std = None

        unique_labels = set(l for l in labels if l != "HATA")
        label_consistent = "Evet" if len(unique_labels) == 1 and len(valid_scores) == REPEAT_COUNT else "Hayır"

        consistency_rows.append({
            "vuln_id": vuln_id,
            "cvss": row.get("cvss_score"),
            "scores": scores,
            "labels": labels,
            "max_diff": score_diff,
            "std_dev": score_std,
            "consistent": label_consistent,
        })
        print(f"  {vuln_id}: Skorlar={scores} | Etiketler={labels} | Fark={score_diff}")

    return consistency_rows


def generate_error_report():
    inv_df = pd.read_csv(INVENTORY_PATH)
    res_df = pd.read_csv(RESULTS_PATH)
    exp_df = pd.read_csv(EXPERT_PATH)

    # Tüm kayıtları (atlanan V014 dahil) sol birleştirme (left join) ile yan yana getir
    merged = (
        inv_df[["vuln_id", "name", "component", "cvss_score", "epss_score", "auth_required", "attack_complexity"]]
        .merge(exp_df, on="vuln_id", how="left")
        .merge(res_df, on="vuln_id", how="left")
    )

    merged["risk_label_llm"] = merged["risk_label_llm"].fillna("ATLANDI (HTTP 500)")
    merged["llm_reason"] = merged["llm_reason"].fillna("Model 3 deneme sonunda HTTP 500 hatası nedeniyle yanıt üretemedi.")
    merged["durum"] = merged.apply(
        lambda r: "Eşleşti" if r["label"] == r["risk_label_llm"] else "Uyuşmadı", axis=1
    )

    valid_df = merged[merged["risk_score_llm"].notna()].copy()
    mismatches = merged[merged["durum"] == "Uyuşmadı"].copy()

    # Ortak hata kalıpları istatistikleri
    exact_cvss_copy = (valid_df["risk_score_llm"] == valid_df["cvss_score"]).sum()
    score_counts = valid_df["risk_score_llm"].value_counts()
    repeated_scores = score_counts[score_counts > 1].to_dict()
    label_dist_llm = valid_df["risk_label_llm"].value_counts().to_dict()
    label_dist_exp = merged["label"].value_counts().to_dict()

    # Tutarlılık testini çalıştır
    consistency_rows = run_consistency_test(inv_df)

    # Markdown raporu oluştur
    lines = [
        "# Model v1 Hata Analizi Raporu (`phi3:mini`)",
        "",
        "## 1. Genel Bakış ve Kapsam",
        "Bu doküman, Issue #80 kapsamında Model v1 (`ai/model_v1_local_llm.py`) çıktılarının K2 uzman etiketleriyle (`ai/expert_labels.csv`) karşılaştırılmasını, uyuşmayan kayıtların gerekçe bazlı incelemesini, ortak hata kalıplarını ve tekrarlı çalıştırma tutarlılık ölçümlerini içerir.",
        "",
        f"- **Toplam Envanter Kaydı:** {len(merged)}",
        f"- **İşlenen Kayıt:** {len(valid_df)} (Atlanan: {len(merged) - len(valid_df)} - `V014`)",
        f"- **Eşleşen Kayıt:** {(merged['durum'] == 'Eşleşti').sum()} / {len(valid_df)} (%{(merged['durum'] == 'Eşleşti').sum() / len(valid_df) * 100:.2f})",
        f"- **Uyuşmayan / Atlanan Kayıt:** {len(mismatches)}",
        "",
        "---",
        "",
        "## 2. v1 Skorları ve Uzman Etiketleri Karşılaştırma Tablosu (Tüm Kayıtlar)",
        "",
        "| Vuln ID | Bileşen / Başlık | CVSS | EPSS | v1 Skor | v1 Etiket | K2 Etiket | Durum |",
        "|---|---|---:|---:|---:|---|---|---|",
    ]

    for _, r in merged.iterrows():
        v_score = f"{r['risk_score_llm']:.2f}" if pd.notna(r["risk_score_llm"]) else "-"
        lines.append(
            f"| {r['vuln_id']} | {r['name']} | {r['cvss_score']} | {r['epss_score']} | {v_score} | {r['risk_label_llm']} | {r['label']} | {r['durum']} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Uyuşmayan Kayıtlar ve Gerekçe Analizi",
        "",
    ])

    for _, r in mismatches.iterrows():
        v_score = f"{r['risk_score_llm']}" if pd.notna(r["risk_score_llm"]) else "Yok (Atlandı)"
        lines.extend([
            f"### {r['vuln_id']} — {r['name']}",
            f"- **Metrikler:** CVSS: `{r['cvss_score']}` | EPSS: `{r['epss_score']}` | Auth: `{r['auth_required']}` | Karmaşıklık: `{r['attack_complexity']}`",
            f"- **Karşılaştırma:** Model v1: **{r['risk_label_llm']}** (Skor: `{v_score}`) vs. K2 Uzman: **{r['label']}**",
            f"- **Model v1 Gerekçesi:** {r['llm_reason']}",
            f"- **K2 Uzman Gerekçesi:** {r['gerekce']}",
            "",
        ])

    lines.extend([
        "---",
        "",
        "## 4. Tespit Edilen Ortak Hata Kalıpları",
        "",
        "1. **CVSS Skorunu Birebir Kopyalama (Anchoring Bias):**",
        f"   - İşlenen {len(valid_df)} kaydın **{exact_cvss_copy} tanesinde** (`%{exact_cvss_copy / len(valid_df) * 100:.1f}`) `risk_score_llm` değeri, girdi olarak verilen `cvss_score` ile birebir aynı üretilmiştir.",
        "2. **Aynı Skoru Çok Sayıda Kayda Verme (Skor Kümelenmesi):**",
        f"   - Model bağlamsal farkları sayısal skora yansıtamadığı için aynı puanları tekrarlamıştır. Birden fazla kez verilen skorlar: `{repeated_scores}`.",
        "3. **Sınıf Dengesizliği ve 'Yüksek' Etiketine Yığılma:**",
        f"   - **Model v1 Dağılımı:** `{label_dist_llm}`",
        f"   - **K2 Uzman Dağılımı:** `{label_dist_exp}`",
        "   - Model, K2'nin `Orta` (9 kayıt) ve `Düşük` (6 kayıt) olarak ayırdığı bulguların tamamına yakınını `Yüksek` sınıfına yığmıştır.",
        "4. **EPSS ve Önkoşul (Kimlik Doğrulama / Kullanıcı Etkileşimi) Sinyallerini Yok Sayma:**",
        "   - Çok düşük EPSS değerine ve yüksek önkoşullara sahip bulgularda bile (ör. `V017`, `V018`, `V021` gibi düşük CVSS/EPSS'li yapılandırma bulguları) model `Yüksek` kararı vermiştir.",
        "   - `V035` kaydında ise model CVSS (`9.8`) yerine yanlışlıkla EPSS skorunu (`0.00718`) `risk_score_llm` olarak atayıp kaydı `Düşük` etiketlemiştir.",
        "5. **Bağımlılık (Trivy) ve Uygulama Kanıtı Ayrımında Terslik:**",
        "   - Model, uygulama içi kesin yönetici erişimi kanıtı olan `V001` ve `V008` kayıtlarını `Yüksek` seviyesinde bırakırken; kod yolu erişilebilirliği belirsiz olan Trivy bağımlılık bulgularını (`V022`, `V023`, `V025`, `V027`) `Kritik` olarak etiketlemiştir.",
        "",
        "---",
        "",
        "## 5. Tutarlılık Testi (Aynı Kaydın 3 Kez Çalıştırılması)",
        "",
        f"`temperature=0.1` ayarında seçilen {len(CONSISTENCY_SAMPLES)} temsili kaydın art arda {REPEAT_COUNT} kez çalıştırılmasıyla elde edilen skor ve etiket değişimleri:",
        "",
        "| Vuln ID | Girdi CVSS | 1. Çalıştırma | 2. Çalıştırma | 3. Çalıştırma | Maks. Skor Farkı | Std. Sapma | Etiket Tutarlı mı? |",
        "|---|---:|---|---|---|---:|---:|---|",
    ])

    for c in consistency_rows:
        r1 = f"{c['scores'][0]} ({c['labels'][0]})" if c["scores"][0] is not None else "HATA"
        r2 = f"{c['scores'][1]} ({c['labels'][1]})" if c["scores"][1] is not None else "HATA"
        r3 = f"{c['scores'][2]} ({c['labels'][2]})" if c["scores"][2] is not None else "HATA"
        diff_str = f"{c['max_diff']}" if c["max_diff"] is not None else "-"
        std_str = f"{c['std_dev']}" if c["std_dev"] is not None else "-"
        lines.append(
            f"| {c['vuln_id']} | {c['cvss']} | {r1} | {r2} | {r3} | {diff_str} | {std_str} | {c['consistent']} |"
        )

    os.makedirs("docs", exist_ok=True)
    with open(OUTPUT_MD_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"\nRapor başarıyla oluşturuldu: {OUTPUT_MD_PATH}")


if __name__ == "__main__":
    generate_error_report()