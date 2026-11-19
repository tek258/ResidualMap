import json
import os
import csv
import math
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

AV_VALS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC_VALS = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
UI_VALS = {"N": 0.85, "R": 0.62}

TARGET_CRITICALITIES = {
    "node_target_admin": 10.0,
    "node_target_rce": 10.0,
    "node_target_account_takeover": 8.0,
    "node_target_leak": 7.0,
    "node_target_dos": 6.0
}


def hesapla_cvss_probabilities(cvss_vector):
    try:
        if not cvss_vector or not isinstance(cvss_vector, str) or not cvss_vector.startswith("CVSS:3.1"):
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


def load_inventory_and_v2(csv_path=None):
    vuln_data = {}
    v2_scores = {}

    base_dir = os.path.dirname(os.path.abspath(__file__))
    if not csv_path:
        possible_csvs = [
            os.path.join(base_dir, '..', 'inventory', 'inventory_v1.0.csv'),
            os.path.join(base_dir, '..', 'inventory_v1.0.csv'),
            'inventory_v1.0.csv'
        ]
        csv_path = next((p for p in possible_csvs if os.path.exists(p)), possible_csvs[0])

    if not os.path.exists(csv_path):
        logging.error(f"Envanter dosyası bulunamadı: {csv_path}")
        return vuln_data, v2_scores

    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            vid = row.get("vuln_id")
            if vid:
                vector = row.get("cvss_vector", "")
                p_score = hesapla_cvss_probabilities(vector)
                if p_score is None:
                    logging.warning(f"[{vid}] için geçerli CVSS vektörü bulunamadı!")
                vuln_data[vid] = {
                    "probability": p_score,
                    "cvss_score": float(row.get("cvss_score", 0.0) or 0.0)
                }

    # AI / V2 skorları: Sadece repodaki ai/ dizininden okunur.
    v2_path = os.path.join(base_dir, '..', 'ai', 'results_v2_llm.csv')
    if not os.path.exists(v2_path):
        v2_path = os.path.join(base_dir, 'ai', 'results_v2_llm.csv')

    if os.path.exists(v2_path):
        with open(v2_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                vid = row.get("vuln_id")
                score = row.get("risk_score_llm")
                if vid and score:
                    try:
                        v2_scores[vid] = float(score)
                    except ValueError:
                        pass
    else:
        logging.warning("AI V2 sonuç dosyası (ai/results_v2_llm.csv) bulunamadı! İkincil skorlar 0 olarak bırakılacak.")

    return vuln_data, v2_scores


def find_attack_paths(edges_file=None, output_file=None, csv_path=None):
    base_dir = os.path.dirname(os.path.abspath(__file__))

    if not edges_file:
        edges_file = os.path.join(base_dir, 'edges.json')
    if not output_file:
        output_file = os.path.join(base_dir, 'paths.json')

    if not os.path.exists(edges_file):
        logging.error(f"Edges dosyası bulunamadı: {edges_file}")
        return None

    vuln_data, v2_scores = load_inventory_and_v2(csv_path)

    with open(edges_file, 'r', encoding='utf-8') as f:
        edges = json.load(f)

    import networkx as nx
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
                    has_missing_vector = False

                    vuln_nodes_in_path = [node for node in path if node.startswith('V')]

                    for v_id in vuln_nodes_in_path:
                        if v_id in vuln_data:
                            p = vuln_data[v_id]["probability"]
                            if p is None:
                                has_missing_vector = True
                            else:
                                probabilities.append(p)
                        else:
                            logging.warning(f"Zafiyet envanterde bulunamadı: {v_id}")
                            has_missing_vector = True

                    if target in TARGET_CRITICALITIES:
                        target_criticality = TARGET_CRITICALITIES[target]
                    else:
                        logging.warning(f"Bilinmeyen hedef düğüm ({target}) tespit edildi!")
                        target_criticality = 5.0

                    if has_missing_vector:
                        path_risk = None
                    else:
                        prod_p = math.prod(probabilities) if probabilities else 0.0
                        path_risk = round(prod_p * target_criticality, 4)

                    path_v2_scores = [v2_scores.get(node, 0.0) for node in vuln_nodes_in_path if node in v2_scores]
                    secondary_v2_score = max(path_v2_scores) if path_v2_scores else 0.0

                    paths_data.append({
                        "source": source,
                        "target": target,
                        "target_name": target,
                        "target_criticality": target_criticality,
                        "path": path,
                        "length": len(path) - 1,
                        "path_risk": path_risk,
                        "secondary_v2_score": secondary_v2_score
                    })

    paths_data.sort(key=lambda x: (x["path_risk"] is not None, x["path_risk"] if x["path_risk"] is not None else 0,
                                   x["secondary_v2_score"]), reverse=True)

    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(paths_data, f, indent=4, ensure_ascii=False)

    logging.info(f"Başarılı! Toplam {len(paths_data)} saldırı yolu hesaplandı ve kaydedildi.")
    return paths_data


def main():
    import os
    base_dir = os.path.dirname(os.path.abspath(__file__))
    edges_path = os.path.join(base_dir, 'edges.json')
    output_path = os.path.join(base_dir, 'paths.json')

    possible_paths = [
        os.path.join(base_dir, '..', 'inventory', 'inventory_v1.0.csv'),
        os.path.join(base_dir, '..', 'inventory_v1.0.csv'),
        'inventory_v1.0.csv'
    ]

    default_csv = next((p for p in possible_paths if os.path.exists(p)), possible_paths[0])

    print(f"Envanter dosyası aranıyor: {default_csv}")
    paths = find_attack_paths(
        edges_file=edges_path,
        output_file=output_path,
        csv_path=default_csv
    )
    if paths is not None:
        print(f"Başarılı! Toplam {len(paths)} saldırı yolu hesaplandı ve kaydedildi.")


if __name__ == '__main__':
    main()