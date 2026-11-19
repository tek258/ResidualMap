import csv
import json
import logging
import os
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

CONTROL_COLUMNS = ["waf", "sanal_yama", "ids", "iam", "segmentasyon", "yama"]

EFFECT_VALUES: Dict[str, float] = {
    "engeller": 0.9,
    "azaltir": 0.5,
    "tespit_eder": 0.2,
    "tespit eder": 0.2,
    "etkisiz": 0.0,
    "kurulmadi": 0.0,
}

CONFIDENCE_MULTIPLIERS: Dict[str, Optional[float]] = {
    "test": 1.0,
    "gerekce": 0.7,
    "varsayim": None,
}


def _normalize_key(val: Optional[str]) -> str:
    return " ".join((val or "").strip().lower().split())


def compute_vulnerability_effectiveness(
    mapping_csv_path: str,
) -> Tuple[Dict[str, dict], List[str]]:
    """
    control_mapping.csv ve docs/olcum-metodolojisi.md kurallarına göre
    her zafiyet için toplam etkinliği ve en yüksek etkili kontrolü hesaplar.
    """
    vuln_map: Dict[str, dict] = {}
    assumption_vulns: List[str] = []

    with open(mapping_csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            vid = (row.get("vuln_id") or "").strip()
            if not vid:
                continue

            dayanak = _normalize_key(row.get("dayanak"))
            confidence = CONFIDENCE_MULTIPLIERS.get(dayanak, None)

            if dayanak == "varsayim":
                assumption_vulns.append(vid)

            active_controls: List[Tuple[str, str, float]] = []
            if confidence is not None:
                for col in CONTROL_COLUMNS:
                    raw_effect = _normalize_key(row.get(col))
                    base_eff = EFFECT_VALUES.get(raw_effect, 0.0)
                    eff = base_eff * confidence
                    if eff > 0.0:
                        active_controls.append((col, raw_effect, eff))

            if active_controls:
                prod_remaining = 1.0
                for _, _, eff in active_controls:
                    prod_remaining *= 1.0 - eff
                total_effectiveness = 1.0 - prod_remaining
                cutting_control = max(active_controls, key=lambda item: item[2])[0]
            else:
                total_effectiveness = 0.0
                cutting_control = None

            vuln_map[vid] = {
                "dayanak": dayanak,
                "total_effectiveness": total_effectiveness,
                "active_controls": active_controls,
                "cutting_control": cutting_control,
            }

    return vuln_map, assumption_vulns


def _edge_vulnerability_id(edge: dict) -> Optional[str]:
    src = (edge.get("source") or "").strip()
    tgt = (edge.get("target") or "").strip()
    rel = (edge.get("relation") or "").strip()

    if src.startswith("node_entry_"):
        return tgt if tgt and not tgt.startswith("node_target_") else None
    if rel == "Chains To":
        return src if src and not src.startswith("node_target_") else None
    return src if src and not src.startswith("node_target_") else None


def determine_edge_status(total_effectiveness: float) -> str:
    if total_effectiveness >= 0.9:
        return "kesildi"
    if total_effectiveness > 0.0:
        return "zayifladi"
    return "acik"


def cut_edges(
    edges_path: Optional[str] = None,
    mapping_csv_path: Optional[str] = None,
    paths_path: Optional[str] = None,
    output_edges_path: Optional[str] = None,
) -> dict:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(base_dir, ".."))

    edges_path = edges_path or os.path.join(base_dir, "edges.json")
    paths_path = paths_path or os.path.join(base_dir, "paths.json")
    output_edges_path = output_edges_path or os.path.join(base_dir, "edges_after.json")

    if not mapping_csv_path:
        candidates = [
            os.path.join(repo_root, "inventory", "control_mapping.csv"),
            os.path.join(repo_root, "control_mapping.csv"),
            os.path.join(base_dir, "control_mapping.csv"),
            "control_mapping.csv",
        ]
        mapping_csv_path = next((p for p in candidates if os.path.exists(p)), candidates[0])

    vuln_eff, assumption_vulns = compute_vulnerability_effectiveness(mapping_csv_path)

    with open(edges_path, mode="r", encoding="utf-8") as f:
        edges = json.load(f)

    edges_after = []
    edge_status_counts = {"kesildi": 0, "zayifladi": 0, "acik": 0}
    edge_status_lookup: Dict[Tuple[str, str], str] = {}

    for edge in edges:
        src = (edge.get("source") or "").strip()
        tgt = (edge.get("target") or "").strip()
        vid = _edge_vulnerability_id(edge)

        v_info = vuln_eff.get(vid or "", {})
        eff = float(v_info.get("total_effectiveness", 0.0))
        status = determine_edge_status(eff)
        cutting_control = v_info.get("cutting_control") if status != "acik" else None

        updated_edge = dict(edge)
        updated_edge["status"] = status
        updated_edge["cutting_control"] = cutting_control
        edges_after.append(updated_edge)

        edge_status_counts[status] += 1
        if src and tgt:
            edge_status_lookup[(src, tgt)] = status

    out_dir = os.path.dirname(output_edges_path) or "."
    os.makedirs(out_dir, exist_ok=True)
    with open(output_edges_path, mode="w", encoding="utf-8") as f:
        json.dump(edges_after, f, ensure_ascii=False, indent=2)

    path_status_counts = {"kesildi": 0, "zayifladi": 0, "acik": 0}
    chain_v002_v025_status = None

    if os.path.exists(paths_path):
        with open(paths_path, mode="r", encoding="utf-8") as f:
            paths_data = json.load(f)

        for p_obj in paths_data:
            nodes = p_obj.get("path", [])
            hop_statuses = [
                edge_status_lookup.get((nodes[i], nodes[i + 1]), "acik")
                for i in range(len(nodes) - 1)
            ]
            if "kesildi" in hop_statuses:
                p_status = "kesildi"
            elif "zayifladi" in hop_statuses:
                p_status = "zayifladi"
            else:
                p_status = "acik"

            path_status_counts[p_status] += 1
            if "V002" in nodes and "V025" in nodes:
                chain_v002_v025_status = p_status

    logging.info(f"edges_after.json üretildi: {output_edges_path}")
    logging.info(f"Kenar durumları -> {edge_status_counts}")
    logging.info(f"Yol durumları -> {path_status_counts}")
    if chain_v002_v025_status is not None:
        logging.info(f"V002 -> V025 zincir yol durumu: {chain_v002_v025_status}")
    if assumption_vulns:
        logging.info(f"Hesaba katılmayan (varsayim) zafiyetler ({len(assumption_vulns)}): {assumption_vulns}")

    return {
        "edges_after": edges_after,
        "edge_status_counts": edge_status_counts,
        "path_status_counts": path_status_counts,
        "chain_v002_v025_status": chain_v002_v025_status,
        "assumption_vulns": assumption_vulns,
    }


if __name__ == "__main__":
    cut_edges()