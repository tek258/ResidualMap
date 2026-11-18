import csv
import json
import os
from pyvis.network import Network


def create_visual_graph(edges_path=None, csv_path=None, output_path=None):
    """Grafiği HTML olarak üretir ve dosya yolunu döndürür.

    Parametreler verilmezse repodaki varsayılan dosyalar kullanılır (komut
    satırından çalıştırma). Uygulama kendi çalıştırma klasörünü verir.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    edges_path = edges_path or os.path.abspath(os.path.join(current_dir, "edges.json"))
    csv_path = csv_path or os.path.abspath(os.path.join(current_dir, "../inventory/inventory_v1.0.csv"))
    output_path = output_path or os.path.abspath(os.path.join(current_dir, "attack_graph_v1.html"))

    if not os.path.exists(edges_path):
        print(f"[HATA] Edges dosyası bulunamadı: {edges_path}")
        return None

    vulnerability_names = {}
    if os.path.exists(csv_path):
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                v_id = row.get("vuln_id", "").strip()
                v_name = row.get("name", "").strip()
                if v_id and v_name:
                    vulnerability_names[v_id] = v_name

    net = Network(height="950px", width="100%", bgcolor="#1a1a1a", font_color="white", directed=True)

    with open(edges_path, "r", encoding="utf-8") as f:
        edges = json.load(f)

    active_nodes = set()
    for edge in edges:
        if edge.get("source"):
            active_nodes.add(edge.get("source"))
        if edge.get("target"):
            active_nodes.add(edge.get("target"))

    for node_id in active_nodes:
        if "node_entry" in node_id:
            # Giriş Noktaları (Level 0)
            label = node_id.replace("node_entry_", "Giriş: ").upper()
            net.add_node(node_id, label=label, title=f"Giriş Vektörü: {node_id}", color="#ff9900", size=30, level=0)

        elif "node_target" in node_id:
            # KRİTİK HEDEFLER (Level 2)
            target_labels = {
                "node_target_admin": "Yetkisiz Admin Erişimi",
                "node_target_leak": "Hassas Veri Sızıntısı",
                "node_target_account_takeover": "Hesap Ele Geçirme",
                "node_target_rce": "RCE ve Sistem Ele Geçirme",
                "node_target_dos": "Hizmet Engelleme (DoS)"
            }
            label = target_labels.get(node_id, node_id.replace("node_target_", "").replace("_", " ").title())
            title_text = f"Kritik Hedef Düğümü\nKimlik: {node_id}\nAçıklama: {label}"

            net.add_node(node_id, label=label, title=title_text, color="#ff4d4d", size=35, level=2)

        else:
            # Zafiyet Düğümleri (Level 1)
            label = vulnerability_names.get(node_id, node_id)
            title_text = f"Zafiyet ID: {node_id}\nİsim: {label}"
            net.add_node(node_id, label=label, title=title_text, color="#3388ff", size=20, level=1)

    # Kenarların eklenmesi ve ilişki türüne göre renklendirilmesi
    for edge in edges:
        source = edge.get("source")
        target = edge.get("target")
        relation = edge.get("relation", "")
        technique = edge.get("technique_name", "")

        hover_title = f"İlişki: {relation}\nTeknik: {technique}"

        # İlişki türüne göre renk kodlaması (Yollar renkli ve takip edilebilir olur)
        if relation == "Entry Point":
            edge_color = "#ff9900"  # Turuncu (Giriş yolları)
        elif relation == "Chains To":
            edge_color = "#3388ff"  # Mavi (Zafiyet zincirleri)
        elif relation == "Leads To":
            edge_color = "#ff4d4d"  # Kırmızı (Hedef sonuçları)
        else:
            edge_color = "#aaaaaa"

        if source and target:
            net.add_edge(
                source, target,
                title=hover_title,
                color=edge_color,
                width=2,
                arrowStrikethrough=False
            )

    net.set_options("""
    {
      "layout": {
        "improvedLayout": true,
        "hierarchical": {
          "enabled": true,
          "direction": "LR",
          "sortMethod": "directed",
          "levelSeparation": 350,
          "nodeSpacing": 180,
          "treeSpacing": 220,
          "blockShifting": true,
          "edgeMinimization": true,
          "parentCentralization": false
        }
      },
      "physics": {
        "enabled": false
      },
      "nodes": {
        "shape": "box",
        "margin": 12,
        "widthConstraint": {
          "maximum": 200
        },
        "font": {
          "size": 14,
          "face": "Arial",
          "color": "#FFFFFF",
          "bold": false
        },
        "borderWidth": 1,
        "shadow": true
      },
      "edges": {
        "width": 1.5,
        "arrows": {
          "to": {
            "enabled": true,
            "scaleFactor": 0.8
          }
        },
        "smooth": {
          "enabled": true,
          "type": "cubicBezier",
          "forceDirection": "horizontal",
          "roundness": 0.3
        },
        "color": {
          "inherit": false,
          "opacity": 0.65
        }
      },
      "interaction": {
        "dragNodes": true,
        "zoomView": true,
        "dragView": true,
        "hover": true,
        "navigationButtons": true,
        "hideEdgesOnDrag": true
      }
    }
    """)

    net.save_graph(output_path)
    print(f"[BAŞARILI] Renkli yollar ve optimize dikey yerleşim uygulandı: {output_path}")
    return output_path


if __name__ == "__main__":
    create_visual_graph()