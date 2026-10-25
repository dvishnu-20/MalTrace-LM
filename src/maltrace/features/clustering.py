"""
Campaign Clustering & Threat Hunting Engine.
Clusters multiple execution traces using behavioral similarity and ATT&CK profile distances
to discover coordinated adversary campaigns, shared delivery infrastructure, and polymorphic toolsets.
"""

from pathlib import Path
from typing import Dict, Any, List, Set, Union, Optional, Sequence
from collections import Counter, defaultdict
import numpy as np
from pydantic import BaseModel, Field
from sklearn.cluster import AgglomerativeClustering

from maltrace.ingestion.loader import load_trace_file
from maltrace.representation.normalizer import normalize_trace_events
from maltrace.attack_mapping.mapper import map_behavior_to_attack
from maltrace.models.feature_extractor import extract_single_structured_vector


class ClusterDetail(BaseModel):
    cluster_id: int
    cluster_label: str
    sample_ids: List[str]
    sample_count: int
    dominant_family: str
    shared_techniques: List[str]
    shared_processes: List[str]
    shared_network_endpoints: List[str]
    cohesion_score: float


class CampaignClusteringResult(BaseModel):
    total_samples: int
    num_clusters: int
    clusters: List[ClusterDetail]
    unclustered_samples: List[str] = Field(default_factory=list)
    summary: str


def cluster_trace_samples(
    sample_paths: Sequence[Union[str, Path]],
    distance_threshold: float = 0.55
) -> CampaignClusteringResult:
    """
    Cluster a collection of trace JSON files based on behavioral features, APIs, and ATT&CK profiles.
    """
    if not sample_paths:
        return CampaignClusteringResult(
            total_samples=0,
            num_clusters=0,
            clusters=[],
            summary="No samples provided for clustering."
        )

    samples_data = []
    feature_vectors = []

    for p in sample_paths:
        path_obj = Path(p)
        if not path_obj.exists() or not path_obj.suffix.lower() == ".json":
            continue

        raw = load_trace_file(path_obj)
        norm = normalize_trace_events(raw.events)
        preds = map_behavior_to_attack(norm, [])
        vec = extract_single_structured_vector(norm)

        tids = set(p.technique_id for p in preds)
        procs = set(e.safe_arguments.get("image_name", "") for e in norm if e.category == "process")
        procs.discard("")

        nets = set()
        for e in norm:
            if e.category == "network":
                dest = str(e.safe_arguments.get("destination_ip", "") or e.safe_arguments.get("remote_address", "")).strip()
                if dest and dest not in ("127.0.0.1", "localhost"):
                    nets.add(dest)

        samples_data.append({
            "sample_id": raw.sample_id,
            "path": str(path_obj),
            "events": norm,
            "techniques": tids,
            "processes": procs,
            "endpoints": nets,
            "feature_vector": vec
        })
        feature_vectors.append(vec)

    if not samples_data:
        return CampaignClusteringResult(
            total_samples=0,
            num_clusters=0,
            clusters=[],
            summary="No valid JSON traces parsed."
        )

    n_samples = len(samples_data)
    if n_samples == 1:
        s0 = samples_data[0]
        return CampaignClusteringResult(
            total_samples=1,
            num_clusters=1,
            clusters=[
                ClusterDetail(
                    cluster_id=0,
                    cluster_label=f"Campaign-0 ({s0['sample_id']})",
                    sample_ids=[s0["sample_id"]],
                    sample_count=1,
                    dominant_family="Single Sample",
                    shared_techniques=sorted(list(s0["techniques"])),
                    shared_processes=sorted(list(s0["processes"])),
                    shared_network_endpoints=sorted(list(s0["endpoints"])),
                    cohesion_score=1.0
                )
            ],
            summary=f"Single trace analyzed: {s0['sample_id']}."
        )

    # Compute custom pairwise distance matrix combining normalized vector Euclidean distance and Jaccard distance on techniques
    X = np.array(feature_vectors, dtype=float)
    # Normalize features
    norms = np.linalg.norm(X, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    X_norm = X / norms

    dist_matrix = np.zeros((n_samples, n_samples))
    for i in range(n_samples):
        for j in range(i, n_samples):
            if i == j:
                dist_matrix[i, j] = 0.0
            else:
                # Cosine distance on feature vector
                cos_dist = 0.5 * (1.0 - np.dot(X_norm[i], X_norm[j]))
                
                # Jaccard distance on techniques
                t_i = samples_data[i]["techniques"]
                t_j = samples_data[j]["techniques"]
                if t_i or t_j:
                    jaccard_tech = 1.0 - (len(t_i.intersection(t_j)) / max(1, len(t_i.union(t_j))))
                else:
                    jaccard_tech = 0.0

                combined_dist = 0.5 * cos_dist + 0.5 * jaccard_tech
                dist_matrix[i, j] = combined_dist
                dist_matrix[j, i] = combined_dist

    # Apply Agglomerative Clustering
    n_clust: Any = None
    clusterer = AgglomerativeClustering(
        n_clusters=n_clust,
        distance_threshold=distance_threshold,
        metric="precomputed",
        linkage="average"
    )
    labels = clusterer.fit_predict(dist_matrix)

    clusters_map: Dict[int, List[int]] = defaultdict(list)
    for idx, lbl in enumerate(labels):
        clusters_map[lbl].append(idx)

    result_clusters: List[ClusterDetail] = []
    for c_id, sample_indices in clusters_map.items():
        c_samples = [samples_data[i] for i in sample_indices]
        s_ids = [s["sample_id"] for s in c_samples]

        # Calculate intersections
        shared_techs = set(c_samples[0]["techniques"])
        shared_procs = set(c_samples[0]["processes"])
        shared_nets = set(c_samples[0]["endpoints"])

        for s in c_samples[1:]:
            shared_techs = shared_techs.intersection(s["techniques"])
            shared_procs = shared_procs.intersection(s["processes"])
            shared_nets = shared_nets.intersection(s["endpoints"])

        # Cohesion score (average intra-cluster pairwise similarity)
        if len(sample_indices) > 1:
            pairs = []
            for i in sample_indices:
                for j in sample_indices:
                    if i < j:
                        pairs.append(1.0 - dist_matrix[i, j])
            cohesion = float(np.mean(pairs)) if pairs else 1.0
        else:
            cohesion = 1.0

        label_name = f"Threat-Cluster-{c_id+1} ({len(s_ids)} samples)"
        result_clusters.append(
            ClusterDetail(
                cluster_id=c_id,
                cluster_label=label_name,
                sample_ids=s_ids,
                sample_count=len(s_ids),
                dominant_family=f"Campaign-{c_id+1}",
                shared_techniques=sorted(list(shared_techs)),
                shared_processes=sorted(list(shared_procs)),
                shared_network_endpoints=sorted(list(shared_nets)),
                cohesion_score=round(cohesion, 3)
            )
        )

    summary = (
        f"Campaign Clustering Analysis: {n_samples} traces grouped into {len(result_clusters)} "
        f"behavioral clusters (distance threshold = {distance_threshold})."
    )

    return CampaignClusteringResult(
        total_samples=n_samples,
        num_clusters=len(result_clusters),
        clusters=result_clusters,
        summary=summary
    )
