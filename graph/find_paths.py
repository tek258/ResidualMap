import json
import os
import csv
import math
import logging
import networkx as nx

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

AV_VALS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC_VALS = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
UI_VALS = {"N": 0.85, "R": 0.62}
CIA_VALS = {"H": 0.56, "L": 0.22, "N": 0.0}


def hesapla_cvss_probabilities(cvss_vector):
    try:
        if not cvss_vector or not cvss_vector.startswith("CVSS:3.1"):
            return None
        parcalar = dict(p.split(":") for p in cvss_vector.strip().split("/")[1:])
        degisti = parcalar.get("S") == "C"
        av = AV_VALS.get(parcalar.get("AV"), 0.85)
        ac = AC_VALS.get(parcalar.get("AC"), 0.77)
        pr_dict = PR_C if degisti else PR_U
        pr = pr_dict.get(parcalar.get("PR"), 0.85)
        ui = UI_VALS.get(parcalar.get("UI"), 0.85)
        saldirilabilirlik = 8.22 * av * ac * pr * ui
        p_val = saldirilabilirlik / 3.887
        return round(min(p_val, 1.0), 4)
    except Exception as e:
        logging.warning(f"CVSS vektör ayrıştırma hatası ({cvss_vector}): {e}")
        return None


def load_inventory_and_v2(base_dir):
    vuln_data = {}

    # Envanter dosyasının olası yolları (inventory/ altında veya ana dizinde)
    possible_inv_paths = [
        os.path.join(base_dir, "..", "inventory", "inventory_v1.0.csv"),
        os.path.join(base_dir, "inventory", "inventory_v1.0.csv"),
        os.path.join(base_dir, "..", "inventory_v1.0.csv"),
        os.path.abspath("inventory/inventory_v1.0.csv"),
        os.path.abspath("inventory_v1.0.csv")
    ]

    inv_file = next((p for p in possible_inv_paths if os.path.exists(p)), None)

    if inv_file:
        with open(inv_file, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                vid = row.get("vuln_id")
                if vid:
                    vector = row.get("cvss_vector", "")
                    p_score = hesapla_cvss_probabilities(vector)
                    if p_score is None:
                        logging.warning(f"[{vid}] için geçerli CVSS vektörü bulunamadı!")
                        p_score = 0.5
                    try:
                        crit = float(row.get("asset_criticality", 5.0))
                    except ValueError:
                        crit = 5.0
                    vuln_data[vid] = {"probability": p_score, "criticality": crit}
    else:
        logging.error("Envanter dosyası (inventory_v1.0.csv) hiçbir konumda bulunamadı!")

    v2_scores = {}
    possible_v2_paths = [
        os.path.join(base_dir, "..", "ai", "results_v2_llm.csv"),
        os.path.join(base_dir, "ai", "results_v2_llm.csv"),
        os.path.abspath("ai/results_v2_llm.csv")
    ]
    v2_file = next((p for p in possible_v2_paths if os.path.exists(p)), None)

    if v2_file:
        with open(v2_file, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                vid = row.get("vuln_id")
                score = row.get("risk_score_llm")
                if vid and score:
                    try:
                        v2_scores[vid] = float(score)
                    except ValueError:
                        pass
    return vuln_data, v2_scores


def find_attack_paths(edges_file=None, output_file=None):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    edges_file = edges_file or os.path.join(base_dir, 'edges.json')
    output_file = output_file or os.path.join(base_dir, 'paths.json')

    if not os.path.exists(edges_file):
        print(f"Hata: {edges_file} dosyası bulunamadı!")
        return None

    with open(edges_file, 'r', encoding='utf-8') as f:
        edges = json.load(f)

    vuln_data, v2_scores = load_inventory_and_v2(base_dir)

    G = nx.DiGraph()
    for edge in edges:
        src = edge.get('source')
        tgt = edge.get('target')
        relation = edge.get('relation', '')
        technique = edge.get('technique_name', '')
        vuln_id = edge.get('vuln_id') or (src if src.startswith('V') else None)
        if src and tgt:
            G.add_edge(src, tgt, relation=relation, technique_name=technique, vuln_id=vuln_id)

    entry_nodes = [node for node in G.nodes() if node.startswith('node_entry_')]
    target_nodes = [node for node in G.nodes() if node.startswith('node_target_')]

    paths_data = []
    for source in entry_nodes:
        for target in target_nodes:
            if nx.has_path(G, source, target):
                for path in nx.all_simple_paths(G, source, target):
                    probabilities = []
                    target_criticality = 10.0
                    for i in range(len(path) - 1):
                        u, v = path[i], path[i + 1]
                        edge_data = G.get_edge_data(u, v)
                        v_id = edge_data.get('vuln_id') if edge_data else None
                        if not v_id and v.startswith('V'):
                            v_id = v
                        elif not v_id and u.startswith('V'):
                            v_id = u
                        if v_id and v_id in vuln_data:
                            probabilities.append(vuln_data[v_id]["probability"])
                            target_criticality = max(target_criticality, vuln_data[v_id]["criticality"])

                    prod_p = math.prod(probabilities) if probabilities else 0.0
                    path_risk = round(prod_p * target_criticality, 4)
                    path_v2_scores = [v2_scores.get(node, 0.0) for node in path if node in v2_scores]
                    secondary_v2_score = max(path_v2_scores) if path_v2_scores else 0.0

                    paths_data.append({
                        "source": source,
                        "target": target,
                        "target_name": target,
                        "path": path,
                        "length": len(path) - 1,
                        "path_risk": path_risk,
                        "secondary_v2_score": secondary_v2_score
                    })

    paths_data.sort(key=lambda x: (x["path_risk"], x["secondary_v2_score"]), reverse=True)

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(paths_data, f, indent=4, ensure_ascii=False)

    print(f"Başarılı! Toplam {len(paths_data)} saldırı yolu hesaplandı ve kaydedildi.")
    return paths_data


if __name__ == '__main__':
    find_attack_paths()