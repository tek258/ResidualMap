import json
import networkx as nx
import os

# Zafiyet sömürü olasılıkları (EPSS / operasyonel katsayılar)
VULN_PROBABILITIES = {
    "V001": 0.70, "V002": 0.40, "V003": 0.50, "V004": 0.60, "V005": 0.45,
    "V006": 0.35, "V007": 0.55, "V008": 0.65, "V009": 0.30, "V010": 0.40,
    "V011": 0.50, "V012": 0.30, "V013": 0.60, "V014": 0.75, "V015": 0.50,
    "V016": 0.40, "V017": 0.45, "V018": 0.35, "V019": 0.50, "V020": 0.40,
    "V021": 0.30, "V022": 0.65, "V023": 0.55, "V024": 0.40, "V025": 0.50,
    "V026": 0.45, "V027": 0.35, "V028": 0.70, "V029": 0.50, "V030": 0.60,
    "V031": 0.80, "V032": 0.40, "V033": 0.35, "V034": 0.50, "V035": 0.45,
    "V036": 0.30
}

# Hedef varlık kritiklik skorları (C_target)
TARGET_CRITICALITIES = {
    "node_target_admin": 10.0,
    "node_target_rce": 10.0,
    "node_target_account_takeover": 9.0,
    "node_target_leak": 8.0,
    "node_target_dos": 6.0
}


def calculate_path_risk(path_nodes, target_name):
    """
    Sömürülme Olasılıklarının Çarpımı × Hedef Kritikliği modelini uygular.
    Risk = (P_1 * P_2 * ... * P_n) * C_target
    """
    prob_product = 1.0
    has_vuln = False

    for node in path_nodes:
        if node in VULN_PROBABILITIES:
            prob_product *= VULN_PROBABILITIES[node]
            has_vuln = True

    if not has_vuln:
        prob_product = 0.5

    target_criticality = TARGET_CRITICALITIES.get(target_name, 5.0)
    risk_score = prob_product * target_criticality
    return round(risk_score, 4)


def find_attack_paths(edges_file=None, output_file=None):
    """Yolları bulur, her yol için risk hesaplar, sıralar ve output_file'a yazar.

    Parametreler verilmezse graph/edges.json ve graph/paths.json kullanılır
    (komut satırından çalıştırma). Uygulama kendi çalıştırma klasörünü verir.
    """
    # Betiğin bulunduğu konum
    base_dir = os.path.dirname(os.path.abspath(__file__))
    edges_file = edges_file or os.path.join(base_dir, 'edges.json')
    output_file = output_file or os.path.join(base_dir, 'paths.json')

    # 1. edges.json dosyasının var olup olmadığını kontrol ediyoruz
    if not os.path.exists(edges_file):
        print(f"Hata: {edges_file} dosyası bulunamadı!")
        return None

    # 2. Dosyanın belleğe yüklenmesi
    with open(edges_file, 'r', encoding='utf-8') as f:
        edges = json.load(f)

    print(f"Toplam {len(edges)} adet kenar başarıyla yüklendi.")

    # 3. NetworkX Yönlü Grafını (DiGraph) Oluşturma
    G = nx.DiGraph()
    for edge in edges:
        src = edge.get('source')
        tgt = edge.get('target')
        relation = edge.get('relation', '')
        technique = edge.get('technique_name', '')
        if src and tgt:
            G.add_edge(src, tgt, relation=relation, technique_name=technique)

    # 4. Giriş ve Hedef Düğümleri Belirleme
    entry_nodes = [node for node in G.nodes() if node.startswith('node_entry_')]
    target_nodes = [node for node in G.nodes() if node.startswith('node_target_')]

    print(f"Bulunan Giriş Düğümleri: {entry_nodes}")
    print(f"Bulunan Hedef Düğümleri: {target_nodes}")

    paths_data = []

    # 5. Her giriş düğümünden her hedef düğüme giden basit yolları hesaplama
    for source in entry_nodes:
        for target in target_nodes:
            if nx.has_path(G, source, target):
                for path in nx.all_simple_paths(G, source, target):
                    # Risk skorunun hesaplanması
                    path_risk = calculate_path_risk(path, target)

                    path_info = {
                        "source": source,
                        "target": target,
                        "target_name": target,
                        "path": path,
                        "length": len(path) - 1,  # Kenar sayısı bazlı uzunluk
                        "path_risk": path_risk
                    }
                    paths_data.append(path_info)

    # 6. Yolları risk skoruna göre büyükten küçüğe (en yüksek risk en üstte olacak şekilde) sıralama
    paths_data = sorted(paths_data, key=lambda x: x["path_risk"], reverse=True)

    # 7. Sonuçları paths.json dosyasına kaydetme
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(paths_data, f, indent=4, ensure_ascii=False)

    print(
        f"Başarılı! Toplam {len(paths_data)} saldırı yolu bulundu, riskleri hesaplandı ve '{output_file}' dosyasına kaydedildi.")
    return paths_data


if __name__ == '__main__':
    find_attack_paths()