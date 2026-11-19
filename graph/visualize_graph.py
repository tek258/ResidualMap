import csv
import json
import logging
import os
import re
from pyvis.network import Network

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

NODE_STYLES = {
    "entry": {"color": "#2ecc71", "shape": "diamond", "size": 26},
    "target": {"color": "#3498db", "shape": "star", "size": 30},
}

TARGET_LABELS = {
    "node_target_admin": "Yetkisiz Admin Erişimi",
    "node_target_leak": "Hassas Veri Sızıntısı",
    "node_target_account_takeover": "Hesap Ele Geçirme",
    "node_target_rce": "RCE ve Sistem Ele Geçirme",
    "node_target_dos": "Hizmet Engelleme (DoS)",
}

GRANTS_TARGET_CAPABILITIES = {
    "admin_session",
    "admin_credentials",
    "forged_identity",
    "stolen_session",
}


def _first_sentence(text):
    cleaned = " ".join((text or "").strip().split())
    if not cleaned:
        return "-"
    match = re.match(r"^(.+?[.!?])(?:\s|$)", cleaned)
    return match.group(1) if match else cleaned


def _extract_cve(text):
    m = re.search(r"CVE-\d{4}-\d+", text or "", re.IGNORECASE)
    return m.group(0).upper() if m else ""


def _resolve_file(explicit_path, candidates):
    if explicit_path and os.path.exists(explicit_path):
        return explicit_path
    for p in candidates:
        if p and os.path.exists(p):
            return p
    return None


def _pick_field(row, candidates):
    for key in candidates:
        if key in row and str(row.get(key) or "").strip() != "":
            return str(row.get(key)).strip()
    lower_map = {str(k).strip().lower(): v for k, v in row.items() if k is not None}
    for key in candidates:
        val = lower_map.get(key.lower())
        if val is not None and str(val).strip() != "":
            return str(val).strip()
    return ""


def _format_target_basis(grants_capability):
    cap = (grants_capability or "").strip()
    if cap in GRANTS_TARGET_CAPABILITIES:
        return f"yetkinlik: {cap}"
    return "CWE kümesi"


def _derive_edge_vuln_id(edge, src, tgt):
    explicit_vid = (edge.get("vuln_id") or "").strip()
    if explicit_vid:
        return explicit_vid
    src_str = (src or "").strip()
    tgt_str = (tgt or "").strip()
    if src_str.startswith("node_entry_"):
        return tgt_str if tgt_str and not tgt_str.startswith("node_target_") else "-"
    return src_str if src_str and not src_str.startswith("node_target_") else "-"


def load_epss_by_cve(epss_csv_path=None):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = _resolve_file(
        epss_csv_path,
        [
            os.path.join(base_dir, "..", "ai", "cvss_epss_scores.csv"),
            os.path.join(base_dir, "cvss_epss_scores.csv"),
            "cvss_epss_scores.csv",
        ],
    )
    epss_map = {}
    if path:
        with open(path, mode="r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                cve = (row.get("cve_id") or "").strip().upper()
                score = (row.get("epss_score") or "").strip()
                if cve and score and score.lower() != "nan":
                    epss_map[cve] = score
    return epss_map


def load_llm_results(llm_csv_path=None):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = _resolve_file(
        llm_csv_path,
        [
            os.path.join(base_dir, "..", "ai", "results_v2_llm.csv"),
            os.path.join(base_dir, "results_v2_llm.csv"),
            "results_v2_llm.csv",
        ],
    )
    llm_map = {}
    v2_available = bool(path and os.path.exists(path))
    if v2_available:
        with open(path, mode="r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                vid = _pick_field(row, ["vuln_id", "id", "cve_id"])
                if vid:
                    llm_map[vid] = {
                        "ai_score": _pick_field(
                            row, ["risk_score_llm", "ai_score", "ai_risk_score", "risk_score"]
                        ),
                        "ai_label": _pick_field(
                            row, ["risk_label_llm", "ai_label", "risk_label"]
                        ),
                        "llm_reason": _pick_field(
                            row,
                            ["llm_reason", "ai_reason", "ai_rationale", "reason", "rationale"],
                        ),
                    }
    return llm_map, v2_available


def load_inventory_details(csv_path=None, llm_csv_path=None, epss_csv_path=None):
    details = {}
    base_dir = os.path.dirname(os.path.abspath(__file__))
    inv_path = _resolve_file(
        csv_path,
        [
            os.path.join(base_dir, "..", "inventory", "inventory_v1.0.csv"),
            os.path.join(base_dir, "..", "inventory_v1.0.csv"),
            "inventory_v1.0.csv",
        ],
    )

    epss_by_cve = load_epss_by_cve(epss_csv_path)
    llm_by_vid, _ = load_llm_results(llm_csv_path)

    if inv_path:
        with open(inv_path, mode="r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                vid = _pick_field(row, ["vuln_id", "id", "cve_id"])
                if not vid:
                    continue

                name = _pick_field(row, ["name", "vuln_name", "title"])
                notes = _pick_field(row, ["notes"])
                grants_cap = _pick_field(row, ["grants_capability"])
                cve_id = _extract_cve(f"{name} {notes}")
                epss_val = epss_by_cve.get(cve_id, "-") if cve_id else "-"

                llm_info = llm_by_vid.get(vid, {})
                raw_ai_score = (llm_info.get("ai_score") or "").strip()
                if raw_ai_score and raw_ai_score.lower() != "nan":
                    ai_score_display = raw_ai_score
                else:
                    ai_score_display = "henüz yok"

                ai_reason_raw = (llm_info.get("llm_reason") or "").strip()
                reason_first = _first_sentence(ai_reason_raw) if ai_reason_raw else "-"

                details[vid] = {
                    "name": name,
                    "cwe_id": _pick_field(row, ["cwe_id", "cwe"]),
                    "cvss_score": _pick_field(row, ["cvss_score", "cvss"]),
                    "epss": epss_val,
                    "ai_score": ai_score_display,
                    "ai_label": llm_info.get("ai_label") or "-",
                    "ai_first_sentence": reason_first,
                    "grants_capability": grants_cap,
                    "target_basis": _format_target_basis(grants_cap),
                    "entry_point": _pick_field(row, ["entry_point"]),
                }

    for vid, llm_info in llm_by_vid.items():
        if vid not in details:
            raw_ai_score = (llm_info.get("ai_score") or "").strip()
            ai_score_display = (
                raw_ai_score if (raw_ai_score and raw_ai_score.lower() != "nan") else "henüz yok"
            )
            details[vid] = {
                "name": vid,
                "cwe_id": "-",
                "cvss_score": "-",
                "epss": "-",
                "ai_score": ai_score_display,
                "ai_label": llm_info.get("ai_label") or "-",
                "ai_first_sentence": _first_sentence(llm_info.get("llm_reason", "")),
                "grants_capability": "",
                "target_basis": "CWE kümesi",
                "entry_point": "-",
            }

    return details


def _strip_bootstrap_cdn(html_content):
    cleaned_lines = []
    for line in html_content.splitlines():
        if "cdn.jsdelivr.net" in line.lower() and "bootstrap" in line.lower():
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def _write_html_utf8(net, output_html):
    if hasattr(net, "generate_html"):
        html_str = _strip_bootstrap_cdn(net.generate_html(notebook=False))
        with open(output_html, "w", encoding="utf-8") as f:
            f.write(html_str)
        return

    try:
        net.write_html(output_html, notebook=False)
        with open(output_html, "r", encoding="utf-8") as f:
            html_str = _strip_bootstrap_cdn(f.read())
        with open(output_html, "w", encoding="utf-8") as f:
            f.write(html_str)
    except UnicodeEncodeError:
        if hasattr(net, "html") and isinstance(net.html, str):
            with open(output_html, "w", encoding="utf-8") as f:
                f.write(_strip_bootstrap_cdn(net.html))
        else:
            raise


def _get_vuln_risk_style(score_str):
    try:
        score = float(score_str)
    except (TypeError, ValueError):
        return "#f39c12", "Orta (Varsayılan)"
    if score >= 8.0:
        return "#e74c3c", "Yüksek (>= 8.0)"
    if score >= 6.0:
        return "#f39c12", "Orta (6.0 - 7.9)"
    return "#f9e79f", "Düşük (< 6.0)"


def visualize_graph(
    edges_file=None,
    paths_file=None,
    output_html=None,
    csv_path=None,
    top_n=5,
):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    edges_file = edges_file or os.path.join(base_dir, "edges.json")
    paths_file = paths_file or os.path.join(base_dir, "paths.json")
    output_html = output_html or os.path.join(base_dir, "attack_graph_v2.html")

    if not os.path.exists(edges_file):
        logging.error(f"Edges dosyası bulunamadı: {edges_file}")
        return None

    with open(edges_file, "r", encoding="utf-8") as f:
        edges = json.load(f)

    paths_data = []
    if os.path.exists(paths_file):
        with open(paths_file, "r", encoding="utf-8") as f:
            paths_data = json.load(f)
    else:
        logging.warning(f"Paths dosyası bulunamadı ({paths_file}), en riskli yol vurgusu yapılmayacak.")

    inv_details = load_inventory_details(csv_path)
    epss_by_cve = load_epss_by_cve()

    for edge in edges:
        src = (edge.get("source") or "").strip()
        tgt = (edge.get("target") or "").strip()
        tech = (edge.get("technique_name") or "").strip()
        vid = _derive_edge_vuln_id(edge, src, tgt)

        if vid and vid != "-":
            cve_from_edge = _extract_cve(tech)
            if cve_from_edge and inv_details.get(vid, {}).get("epss") in ("", "-"):
                if cve_from_edge in epss_by_cve:
                    inv_details.setdefault(vid, {})["epss"] = epss_by_cve[cve_from_edge]

    valid_paths = [p for p in paths_data if p.get("path_risk") is not None]
    top_paths = valid_paths[:top_n]

    top_edges = set()
    path_rank_map = {}

    for idx, p_obj in enumerate(top_paths, start=1):
        p_nodes = p_obj.get("path", [])
        for n in p_nodes:
            path_rank_map.setdefault(n, []).append(f"#{idx} (Risk: {p_obj.get('path_risk')})")
        for i in range(len(p_nodes) - 1):
            top_edges.add((p_nodes[i], p_nodes[i + 1]))

    net = Network(
        height="900px",
        width="100%",
        directed=True,
        bgcolor="#141820",
        font_color="#f5f7fa",
        cdn_resources="local",
    )

    net.barnes_hut(
        gravity=-4500,
        central_gravity=0.3,
        spring_length=160,
        spring_strength=0.05,
        damping=0.09,
    )

    added_nodes = set()

    def ensure_node(node_id):
        if node_id in added_nodes:
            return
        added_nodes.add(node_id)

        if node_id.startswith("node_entry_"):
            style = NODE_STYLES["entry"]
            tooltip = f"Giriş Düğümü: {node_id}\nTür: Giriş Noktası"
            label = node_id
            color = style["color"]
            shape = style["shape"]
            size = style["size"]
        elif node_id.startswith("node_target_"):
            style = NODE_STYLES["target"]
            desc = TARGET_LABELS.get(
                node_id,
                node_id.replace("node_target_", "").replace("_", " ").title(),
            )
            tooltip = f"Hedef Düğümü: {node_id}\nTür: Hedef\nAçıklama: {desc}"
            label = node_id
            color = style["color"]
            shape = style["shape"]
            size = style["size"]
        else:
            info = inv_details.get(node_id, {})
            ai_score_val = (info.get("ai_score") or "").strip()
            has_ai_score = bool(
                ai_score_val and ai_score_val not in ("-", "henüz yok", "nan", "None")
            )
            risk_metric = ai_score_val if has_ai_score else info.get("cvss_score")
            color, risk_label = _get_vuln_risk_style(risk_metric)
            shape = "dot"
            size = 20
            label = node_id

            target_basis = info.get("target_basis") or _format_target_basis(
                info.get("grants_capability")
            )
            ai_score_hover = ai_score_val if ai_score_val else "henüz yok"

            tooltip = (
                f"Zafiyet Adı: {info.get('name') or node_id}\n"
                f"CVSS: {info.get('cvss_score') or '-'}\n"
                f"EPSS: {info.get('epss') or '-'}\n"
                f"AI Skoru: {ai_score_hover}\n"
                f"AI Gerekçesi (İlk Cümle): {info.get('ai_first_sentence') or '-'}\n"
                f"Hedef Eşleşmesi Dayanağı: {target_basis}\n"
                f"Zafiyet ID: {node_id} | Risk Tonu: {risk_label}"
            )

        if node_id in path_rank_map:
            tooltip += f"\nTop-{top_n} Yol Sırası: {', '.join(path_rank_map[node_id])}"

        net.add_node(
            node_id,
            label=label,
            title=tooltip,
            color=color,
            shape=shape,
            size=size,
        )

    for edge in edges:
        src = edge.get("source")
        tgt = edge.get("target")
        if not src or not tgt:
            continue

        ensure_node(src)
        ensure_node(tgt)

        relation = edge.get("relation", "")
        technique = edge.get("technique_name", "")
        basis = (edge.get("basis") or "").strip()
        vuln_id = _derive_edge_vuln_id(edge, src, tgt)

        is_top = (src, tgt) in top_edges
        is_estimated_cvss = basis.lower() == "cvss"

        edge_color = "#ff3b30" if is_top else ("#9aa5b1" if is_estimated_cvss else "#5c6bc0")
        edge_width = 4.2 if is_top else 1.8

        hover_text = (
            f"Kaynak: {src} -> Hedef: {tgt}\n"
            f"İlişki: {relation or '-'}\n"
            f"Teknik/Ad: {technique or '-'}\n"
            f"Zafiyet ID: {vuln_id or '-'}\n"
            f"Dayanak (Basis): {basis or '-'}"
            + (" (Tahmini Bağlantı - CVSS)" if is_estimated_cvss else "")
            + ("\nTop-5 Yüksek Riskli Yol" if is_top else "")
        )

        net.add_edge(
            src,
            tgt,
            title=hover_text,
            color=edge_color,
            width=edge_width,
            dashes=is_estimated_cvss,
            arrows="to",
        )

    net.set_options("""
    {
      "physics": {
        "enabled": true,
        "barnesHut": {
          "gravitationalConstant": -4500,
          "centralGravity": 0.3,
          "springLength": 160,
          "springConstant": 0.05,
          "damping": 0.09
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

    out_dir = os.path.dirname(output_html) or "."
    os.makedirs(out_dir, exist_ok=True)
    _write_html_utf8(net, output_html)

    legend_html = """
    <div id="graph-legend" style="
        position: fixed; bottom: 14px; left: 14px; z-index: 9999;
        max-width: 320px; background: rgba(20, 24, 32, 0.92);
        color: #f5f7fa; border: 1px solid #4a5568; border-radius: 8px;
        padding: 10px 14px; font-family: Arial, sans-serif; font-size: 12px;
        box-shadow: 0 4px 16px rgba(0,0,0,0.45);">
        <div style="font-weight: bold; font-size: 13px; color: #90caf9; margin-bottom: 6px;">
            Lejant (Şekiller ve Risk Tonları)
        </div>
        <div style="margin-bottom: 6px; line-height: 1.45;">
            <div><span style="color:#2ecc71; font-weight:bold;">◆</span> Giriş Düğümü (diamond)</div>
            <div><span style="color:#3498db; font-weight:bold;">★</span> Hedef Düğümü (star)</div>
            <div><span style="color:#ff3b30; font-weight:bold;">━</span> Top-5 Yüksek Riskli Yol</div>
            <div><span style="color:#9aa5b1; font-weight:bold;">┄</span> Tahmini Bağlantı (basis: cvss)</div>
        </div>
        <div style="border-top: 1px solid rgba(255,255,255,0.14); padding-top: 6px;">
            <div style="font-weight: bold; margin-bottom: 4px;">Zafiyet Risk Tonu (dot) &mdash; renk: AI skoru (yoksa CVSS)</div>
            <div style="margin: 2px 0;"><span style="color:#e74c3c; font-weight:bold;">●</span> Yüksek (&ge; 8.0)</div>
            <div style="margin: 2px 0;"><span style="color:#f39c12; font-weight:bold;">●</span> Orta (6.0 - 7.9)</div>
            <div style="margin: 2px 0;"><span style="color:#f9e79f; font-weight:bold;">●</span> Düşük (&lt; 6.0)</div>
        </div>
    </div>
    """

    extra_html = ""
    if top_paths:
        summary_items = []
        for idx, p in enumerate(top_paths, start=1):
            chain = " &rarr; ".join(p.get("path", []))
            summary_items.append(
                f"<li><b>#{idx}</b> | Risk: <b>{p.get('path_risk')}</b> | "
                f"Hedef Kritiklik: {p.get('target_criticality')} | {chain}</li>"
            )
        panel_html = f"""
        <div id="top5-panel" style="
            position: fixed; top: 14px; right: 14px; z-index: 9999;
            max-width: 430px; background: rgba(20, 24, 32, 0.92);
            color: #f5f7fa; border: 1px solid #ff3b30; border-radius: 8px;
            padding: 12px 14px; font-family: Arial, sans-serif; font-size: 12px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.45);">
            <div style="font-weight: bold; font-size: 13px; color: #ff6b6b; margin-bottom: 6px;">
                En Riskli {len(top_paths)} Saldırı Yolu (Top-{top_n})
            </div>
            <ol style="margin: 0; padding-left: 18px; line-height: 1.45;">
                {''.join(summary_items)}
            </ol>
        </div>
        """
        extra_html += panel_html + "\n"

    extra_html += legend_html

    with open(output_html, "r", encoding="utf-8") as f:
        html_content = _strip_bootstrap_cdn(f.read())
    if "</body>" in html_content:
        html_content = html_content.replace("</body>", extra_html + "\n</body>")
    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html_content)

    logging.info(f"Graf görselleştirmesi oluşturuldu: {output_html}")
    return output_html


def create_visual_graph(edges_path=None, csv_path=None, output_path=None, paths_path=None):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    resolved_paths = paths_path if paths_path else os.path.join(base_dir, "paths.json")
    return visualize_graph(
        edges_file=edges_path,
        paths_file=resolved_paths,
        output_html=output_path or os.path.join(base_dir, "attack_graph_v2.html"),
        csv_path=csv_path,
    )


if __name__ == "__main__":
    visualize_graph()