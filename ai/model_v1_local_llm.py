import json
import logging
import os
import requests
import pandas as pd

# Logging ayarları
os.makedirs("ai", exist_ok=True)
logging.basicConfig(
    filename="ai/model_v1_execution.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

LOCAL_LLM_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "phi3:mini"

PROMPT_TEMPLATE = """
Sen kıdemli bir siber güvenlik ve zafiyet önceliklendirme uzmanısın.
Aşağıdaki zafiyet kaydını verilen Uzman Etiketleme Ölçütü kurallarına göre analiz et ve risk seviyesi ile gerekçe üret.

### Uzman Etiketleme Ölçütü Kuralları:
- **Kritik**: Yönetici yetkisi elde edilmesi, sistemin bütünüyle ele geçirilmesi veya hassas verilerin geniş ölçekte açığa çıkması; saldırı yolu uygulanabilir, önemli koruma engeli yok. Yüksek CVSS tek başına Kritik yapmaz, uygulamaya özgü kanıt aranır.
- **Yüksek**: Ciddi gizlilik/bütünlük/kullanılabilirlik etkisi; ancak gerekli kimlik doğrulama, yüksek saldırı karmaşıklığı, kullanıcı etkileşimi veya erişilebilirliğin doğrulanmamış olması Kritik seviyesinden ayırır.
- **Orta**: Etki sınırlı bir hesap, veri kümesi veya işlevle sınırlıdır ya da anlamlı kullanıcı etkileşimi/önkoşullar gerekir.
- **Düşük**: Bilgi açıklama veya savunma derinliğini azaltma gibi sınırlı etki; somut bir kayıp gösterilmemiştir.

Zafiyet Detayları:
- Vuln ID: {vuln_id}
- CVE ID: {cve_id}
- İsim/Başlık: {name}
- Bileşen (Component): {component}
- CWE ID: {cwe_id}
- CVSS Skoru: {cvss_score}
- CVSS Vektörü: {cvss_vector}
- EPSS Skoru: {epss_score}
- Maruziyet (Exposure): {exposure}
- Kimlik Doğrulama (Auth Required): {auth_required}
- Saldırı Karmaşıklığı (Attack Complexity): {attack_complexity}
- Varlık Kritikliği (Asset Criticality): {asset_criticality}
- Notlar: {notes}

Çıktıyı YALNIZCA geçerli bir JSON formatında ver, başka hiçbir açıklama veya metin ekleme:
{{
  "risk_score_llm": <0.0 ile 10.0 arasında ondalıklı bir sayı>,
  "risk_label_llm": "<Kritik ya da Yüksek ya da Orta ya da Düşük>",
  "llm_reason": "<Kararın gerekçesini ve dikkate alınan kuralı kısaca açıkla>"
}}
"""

def query_local_llm(prompt):
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }
    try:
        response = requests.post(LOCAL_LLM_URL, json=payload, timeout=90)
        response.raise_for_status()
        result = response.json()
        content = result.get("response", "{}")
        return json.loads(content)
    except Exception as e:
        logging.error(f"LLM sorgu hatası veya geçersiz JSON: {e}")
        return None

def score_vulnerabilities(inventory_path, output_csv_path):
    if not os.path.exists(inventory_path):
        print(f"Hata: Envanter dosyası bulunamadı -> {inventory_path}")
        return None

    df = pd.read_csv(inventory_path)
    results = []
    skipped_count = 0

    print(f"Toplam {len(df)} kayıt işleniyor...")

    for idx, row in df.iterrows():
        vuln_id = row.get("vuln_id", f"unknown_{idx}")
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
            notes=row.get("notes", "Yok")
        )

        llm_resp = query_local_llm(prompt)
        
        # Geçersiz JSON veya eksik anahtar kontrolü (try/except mantığıyla atlama)
        if llm_resp and "risk_score_llm" in llm_resp and "risk_label_llm" in llm_resp:
            results.append({
                "vuln_id": vuln_id,
                "risk_score_llm": float(llm_resp["risk_score_llm"]),
                "risk_label_llm": str(llm_resp["risk_label_llm"]),
                "llm_reason": str(llm_resp.get("llm_reason", ""))
            })
            print(f"[{idx+1}/36] Başarılı: {vuln_id} -> {llm_resp['risk_label_llm']}")
        else:
            skipped_count += 1
            logging.warning(f"Kayıt atlandı (Geçersiz JSON/Yanıt): {vuln_id}")
            print(f"[{idx+1}/36] HATA/Atlandı: {vuln_id}")

    res_df = pd.DataFrame(results)
    res_df.to_csv(output_csv_path, index=False)
    print(f"\nİşlem tamamlandı. Başarılı: {len(results)}, Atlanan: {skipped_count}")
    print(f"Çıktı kaydedildi: {output_csv_path}")
    return res_df

def calculate_metrics(results_df, inventory_path, expert_labels_path):
    if results_df is None or results_df.empty:
        return

    inv_df = pd.read_csv(inventory_path)
    
    # 1. Baseline (CVSS-only) ile Top-10 Örtüşme Oranı
    baseline_top10 = set(inv_df.sort_values(by="cvss_score", ascending=False).head(10)["vuln_id"])
    llm_top10 = set(results_df.sort_values(by="risk_score_llm", ascending=False).head(10)["vuln_id"])
    
    overlap = len(baseline_top10.intersection(llm_top10))
    overlap_ratio = (overlap / 10.0) * 100
    print(f"\n--- METRİKLER ---")
    print(f"Baseline (CVSS) ile Top-10 Örtüşme Oranı: %{overlap_ratio:.1f}")

    # 2. K2 Uzman Etiketleriyle Karşılaştırma
    if os.path.exists(expert_labels_path):
        exp_df = pd.read_csv(expert_labels_path)
        merged = pd.merge(results_df, exp_df, on="vuln_id")
        
        if not merged.empty:
            match_count = (merged["risk_label_llm"] == merged["label"]).sum()
            match_ratio = (match_count / len(merged)) * 100
            print(f"K2 Uzman Etiketleriyle Kategori Uyum Oranı: %{match_ratio:.2f} ({match_count}/{len(merged)} kayıt)")
        else:
            print("Uyarı: inventory vuln_id'leri ile expert_labels.csv eşleşmedi.")
    else:
        print(f"Bilgi: Uzman etiket dosyası henüz bulunamadı ({expert_labels_path}), karşılaştırma atlandı.")

if __name__ == "__main__":
    inventory_file = "inventory/inventory_v1.0.csv"
    output_file = "ai/results_v1_llm.csv"
    expert_file = "ai/expert_labels.csv"
    
    res_df = score_vulnerabilities(inventory_file, output_file)
    calculate_metrics(res_df, inventory_file, expert_file)