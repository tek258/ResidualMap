import json
import networkx as nx
import os


def find_attack_paths(edges_file=None, output_file=None):
    """Yolları bulup output_file'a yazar ve döndürür.

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
                    path_info = {
                        "source": source,
                        "target": target,
                        "target_name": target,
                        "path": path,
                        "length": len(path) - 1  # Kenar sayısı bazlı uzunluk
                    }
                    paths_data.append(path_info)

    # 6. Sonuçları paths.json dosyasına kaydetme
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(paths_data, f, indent=4, ensure_ascii=False)

    print(f"Başarılı! Toplam {len(paths_data)} saldırı yolu bulundu ve '{output_file}' dosyasına kaydedildi.")
    return paths_data


if __name__ == '__main__':
    find_attack_paths()