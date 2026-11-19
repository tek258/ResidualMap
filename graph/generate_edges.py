import json
import os
import csv
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# 5 Hedef Tanımı
TARGET_MAPPING = {
    "admin": "node_target_admin",
    "leak": "node_target_leak",
    "rce": "node_target_rce",
    "dos": "node_target_dos",
    "account_takeover": "node_target_account_takeover"
}

# CWE Kural Tabanlı Eşlemeler (rule)
CWE_RULE_TARGETS = {
    "CWE-89": "node_target_admin",
    "CWE-79": "node_target_account_takeover",
    "CWE-78": "node_target_rce",
    "CWE-22": "node_target_leak",
    "CWE-400": "node_target_dos",
    "CWE-639": "node_target_account_takeover",
    "CWE-693": "node_target_admin",
    "CWE-1321": "node_target_rce",
    "CWE-122": "node_target_rce",
    "CWE-248": "node_target_dos",
    "CWE-476": "node_target_dos",
    "CWE-285": "node_target_admin",
    "CWE-176": "node_target_leak",
    "CWE-290": "node_target_account_takeover",
    "CWE-331": "node_target_leak",
    "CWE-328": "node_target_leak",
    "CWE-94": "node_target_rce",
    "CWE-749": "node_target_rce",
    "CWE-20": "node_target_account_takeover",
    "CWE-497": "node_target_leak",
    "CWE-264": "node_target_admin",
    "CWE-209": "node_target_leak",
    "CWE-521": "node_target_account_takeover",
    "CWE-798": "node_target_admin",
    "CWE-601": "node_target_account_takeover",
    "CWE-352": "node_target_account_takeover",
    "CWE-640": "node_target_account_takeover",
    "CWE-611": "node_target_leak",
    "CWE-548": "node_target_leak",
    "CWE-915": "node_target_admin",
    "CWE-119": "node_target_rce"
}

EXTRA_CWE_MAPPING = {}


def determine_target_and_basis(row):
    cwe = row.get("cwe_id", "").strip()
    notes = row.get("notes", "").lower()

    if cwe in CWE_RULE_TARGETS:
        return CWE_RULE_TARGETS[cwe], "rule"
    if cwe in EXTRA_CWE_MAPPING:
        return EXTRA_CWE_MAPPING[cwe], "extra-cwe"

    if "admin" in notes or "auth" in notes:
        return "node_target_admin", "cvss"
    elif "rce" in notes or "command" in notes or "execution" in notes:
        return "node_target_rce", "cvss"
    elif "leak" in notes or "disclosure" in notes or "read" in notes:
        return "node_target_leak", "cvss"
    elif "dos" in notes or "denial" in notes:
        return "node_target_dos", "cvss"
    else:
        return "node_target_account_takeover", "cvss"


def generate_edges(inventory_file=None, output_file=None):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = output_file or os.path.join(base_dir, 'edges.json')

    # Envanter dosyasının olası yolları
    possible_inv_paths = [
        os.path.join(base_dir, "..", "inventory", "inventory_v1.0.csv"),
        os.path.join(base_dir, "inventory", "inventory_v1.0.csv"),
        os.path.join(base_dir, "..", "inventory_v1.0.csv"),
        os.path.abspath("inventory/inventory_v1.0.csv"),
        os.path.abspath("inventory_v1.0.csv")
    ]
    inventory_file = inventory_file or next((p for p in possible_inv_paths if os.path.exists(p)), None)

    if not inventory_file or not os.path.exists(inventory_file):
        logging.error("Envanter dosyası (inventory_v1.0.csv) hiçbir konumda bulunamadı!")
        return

    edges = []
    basis_counts = {"rule": 0, "extra-cwe": 0, "cvss": 0}

    entry_node_mapping = {
        "login": "node_entry_login",
        "search": "node_entry_search",
        "api": "node_entry_api",
        "web": "node_entry_web",
        "dependency": "node_entry_dependency"
    }

    with open(inventory_file, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            vuln_id = row.get("vuln_id")
            entry_point = row.get("entry_point", "").strip().lower()
            name = row.get("name", "")

            if not vuln_id:
                continue

            if entry_point in entry_node_mapping:
                source_node = entry_node_mapping[entry_point]
            else:
                logging.warning(f"[{vuln_id}] için bilinmeyen/boş entry_point ('{entry_point}'), varsayılan 'node_entry_login' kullanılıyor.")
                source_node = "node_entry_login"

            # 1. Kenar: Giriş Düğümünden Zafiyete
            edges.append({
                "source": source_node,
                "target": vuln_id,
                "relation": "entry_to_vuln",
                "technique_name": f"Access via {entry_point}",
                "vuln_id": vuln_id,
                "basis": "rule"
            })

            # Hedef ve Dayanak Tespiti
            target_node, basis = determine_target_and_basis(row)
            basis_counts[basis] += 1

            # 2. Kenar: Zafiyetten Hedefe
            edges.append({
                "source": vuln_id,
                "target": target_node,
                "relation": "vuln_to_target",
                "technique_name": name,
                "vuln_id": vuln_id,
                "basis": basis
            })

    out_dir = os.path.dirname(output_file) or "."
    os.makedirs(out_dir, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(edges, f, indent=4, ensure_ascii=False)

    print(f"Başarılı! Toplam {len(edges)} kenar üretildi ve kaydedildi.")
    print(f"Dayanak Dağılımı: {basis_counts}")
    return edges


if __name__ == '__main__':
    generate_edges()