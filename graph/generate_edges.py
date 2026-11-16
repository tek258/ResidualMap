import csv
import json
import os

# Proje dizin yapısına göre dosya yollarının dinamik olarak mutlak konumda tanımlanması
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.abspath(os.path.join(CURRENT_DIR, "../inventory/inventory_v1.0.csv"))
OUTPUT_EDGES_PATH = os.path.abspath(os.path.join(CURRENT_DIR, "edges.json"))

# CWE kümeleri: Zafiyetleri siber güvenlik hedeflerine deterministik olarak eşlemek için tanımlanan listeler
ADMIN_CWES = {"cwe-798", "cwe-521", "cwe-20", "cwe-290", "cwe-285", "cwe-915"}
LEAK_CWES = {"cwe-200", "cwe-548", "cwe-611", "cwe-209", "cwe-264", "cwe-497", "cwe-328"}
ACCOUNT_CWES = {"cwe-79", "cwe-639", "cwe-640", "cwe-352", "cwe-601", "cwe-693", "cwe-749", "cwe-331"}
RCE_CWES = {"cwe-1321", "cwe-94", "cwe-22", "cwe-176", "cwe-122", "cwe-119"}
DOS_CWES = {"cwe-400", "cwe-476", "cwe-248"}


# Kazanım (grants_capability) tabanlı hedefler: bir zafiyet bu yetkinlikleri
# kazandırıyorsa, sonucu CWE'den bağımsız olarak bu hedeftir. Örn. V025 (zayıf
# PBKDF2, CWE-328) CWE'ye göre sızıntı hedefine düşerdi, ama admin_credentials
# kazandırdığı için admin hedefine gider. Kayıt numarasına bağlı değildir.
GRANTS_TARGETS = {
    "admin_session": "node_target_admin",
    "admin_credentials": "node_target_admin",
    "forged_identity": "node_target_admin",
    "stolen_session": "node_target_account_takeover",
}


def map_to_target(v_id, name, cwe_id, grants="none"):
    """
    Zafiyetin nihai etki hedefini belirler: önce kazandırdığı yetkinliğe
    (grants_capability), sonra CWE koduna ve adına bakar.
    """
    if grants in GRANTS_TARGETS:
        return GRANTS_TARGETS[grants]

    cwe = cwe_id.lower().strip()
    name_lower = name.lower()

    # CWE-89 (SQL Injection) özel durumu: bağlama göre admin veya leak hedefine yönlendirilir
    if cwe == "cwe-89":
        if "login" in name_lower or "admin" in name_lower:
            return "node_target_admin"
        return "node_target_leak"

    # Standart CWE küme eşlemeleri
    if cwe in ADMIN_CWES:
        return "node_target_admin"
    if cwe in LEAK_CWES:
        return "node_target_leak"
    if cwe in ACCOUNT_CWES:
        return "node_target_account_takeover"
    if cwe in RCE_CWES:
        return "node_target_rce"
    if cwe in DOS_CWES:
        return "node_target_dos"

    # Küme dışı kalsa bile isminde admin geçenler doğrudan admin hedefine bağlanır
    if "admin" in name_lower:
        return "node_target_admin"

    return None


# Hedef düğümlerin teknik teknik isim karşılıkları
TARGET_TECHNIQUE_NAMES = {
    "node_target_admin": "Unauthorized Administrator Access",
    "node_target_leak": "Sensitive Data Exfiltration & Database Exposure",
    "node_target_account_takeover": "Account Takeover via Client-Side Attack",
    "node_target_rce": "Remote Code Execution & System Compromise",
    "node_target_dos": "Denial of Service & Resource Exhaustion",
}


def generate_attack_edges(csv_path=CSV_PATH, output_edges_path=OUTPUT_EDGES_PATH):
    """Kenarları üretip output_edges_path'e yazar ve döndürür.

    Parametreler verilmezse repodaki envanter ve graph/edges.json kullanılır
    (komut satırından çalıştırma). Uygulama kendi çalıştırma klasörünü verir.
    """
    edges = []

    # Envanter dosyasının kontrolü
    if not os.path.exists(csv_path):
        print(f"[HATA] Envanter dosyası bulunamadı: {csv_path}")
        return None

    vulnerabilities = []

    # CSV verilerinin okunması ve normalize edilerek belleğe alınması
    with open(csv_path, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            v_id = row.get("vuln_id", "").strip()
            if not v_id:
                continue
            vulnerabilities.append({
                "id": v_id,
                "name": row.get("name", "").strip(),
                "component": row.get("component", "").strip().lower(),
                "cwe_id": row.get("cwe_id", "").strip().upper(),
                "requires_capability": row.get("requires_capability", "none").strip().lower() or "none",
                "grants_capability": row.get("grants_capability", "none").strip().lower() or "none",
            })

    # Giriş noktaları havuzu
    entry_nodes_pool = [
        ("node_entry_login", "Initial Access via Authentication & Session"),
        ("node_entry_api", "API Interface & Service Exposure"),
        ("node_entry_search", "User Input & Parameter Vector")
    ]

    unmapped_targets = []

    # Zafiyetler üzerinde dönerek giriş ve hedef kenarlarının üretilmesi
    for index, v in enumerate(vulnerabilities):
        v_id = v["id"]
        name = v["name"]
        component = v["component"]
        cwe_id = v["cwe_id"]
        requires = v["requires_capability"]
        name_lower = name.lower()

        # KRİTİK DÜZELTME: Eğer zafiyetin bir ön koşulu (requires) varsa, dışarıdan doğrudan giriş noktası ATAMA!
        if requires == "none":
            if any(k in cwe_id.lower() or k in component or k in name_lower for k in ["287", "798", "auth", "login", "session", "credential"]):
                entry_node, technique_initial = entry_nodes_pool[0]
            elif any(k in cwe_id.lower() or k in component or k in name_lower for k in ["200", "api", "service", "endpoint", "exposure", "proxy", "ws"]):
                entry_node, technique_initial = entry_nodes_pool[1]
            else:
                chosen_entry = entry_nodes_pool[index % len(entry_nodes_pool)]
                entry_node, technique_initial = chosen_entry[0], f"Vector via {chosen_entry[0].replace('node_entry_', '').upper()}"

            edges.append({
                "source": entry_node,
                "target": v_id,
                "relation": "Entry Point",
                "technique_name": technique_initial
            })

        # CWE bazlı hedef eşlemesi ve Leads To kenarının eklenmesi
        target_node = map_to_target(v_id, name, cwe_id, v["grants_capability"])
        if target_node is not None:
            edges.append({
                "source": v_id,
                "target": target_node,
                "relation": "Leads To",
                "technique_name": TARGET_TECHNIQUE_NAMES[target_node]
            })
        else:
            unmapped_targets.append(v_id)

    # Capability (Yetenek) tabanlı mantıksal zincirleme ('Chains To' ilişkileri)
    capability_sources = {}
    for v in vulnerabilities:
        grants = v["grants_capability"]
        if grants != "none":
            capability_sources.setdefault(grants, []).append(v["id"])

    for v in vulnerabilities:
        requires = v["requires_capability"]
        if requires != "none" and requires in capability_sources:
            for source_id in capability_sources[requires]:
                if source_id != v["id"]:
                    edges.append({
                        "source": source_id,
                        "target": v["id"],
                        "relation": "Chains To",
                        "technique_name": f"{requires} elde edilince mümkün olur"
                    })

    # Tekrarlayan ve fazla kenarların temizlenmesi (Unique edges)
    unique_edges = []
    seen = set()
    for e in edges:
        identifier = (e['source'], e['target'], e['relation'])
        if identifier not in seen:
            seen.add(identifier)
            unique_edges.append(e)

    # Üretilen tekil kenar listesinin edges.json dosyasına yazılması
    with open(output_edges_path, "w", encoding="utf-8") as outfile:
        json.dump(unique_edges, outfile, indent=4, ensure_ascii=False)

    # İşlem sonuç raporu
    print(f"[BAŞARILI] Toplam {len(unique_edges)} tekil kenar üretildi: {output_edges_path}")
    if unmapped_targets:
        print(f"[UYARI] {len(unmapped_targets)} zafiyet hiçbir hedefe eşlenemedi: {', '.join(unmapped_targets)}")
    else:
        print("Tüm zafiyetler bir hedefe eşlendi.")
    return unique_edges


if __name__ == "__main__":
    generate_attack_edges()