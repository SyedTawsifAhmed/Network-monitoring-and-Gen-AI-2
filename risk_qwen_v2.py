"""Risk analyzer for network configuration using operation-aware RAG.
 Deterministic safety floors are applied, a quantized Qwen GGUF model 
is used to provide a structured evaluation, pertinent labelled samples 
are retrieved from a cached FAISS database, and a compact JSON record 
is exported for a downstream scoring engine. 
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import faiss
import numpy as np
import torch
from llama_cpp import Llama
from sentence_transformers import SentenceTransformer

LOGGER = logging.getLogger("network-risk-analyzer")

# ----------------------------- Configuration -----------------------------

DATASET_PATH = Path(os.getenv("DATASET_PATH", "all_samples_with_metadata.jsonl"))
MODEL_PATH = Path(os.getenv("MODEL_PATH", "models/Qwen3-8B-Q4_K_M.gguf"))
EMBED_MODEL = os.getenv(
    "EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2"
)
CACHE_DIR = Path(os.getenv("CACHE_DIR", ".rag_cache"))
OUTPUT_PATH = Path(os.getenv("OUTPUT_PATH", "qwen_risk_assessment_output.json"))
OUTPUT_SCHEMA_VERSION = "1.0"

TOP_K = int(os.getenv("TOP_K", "3"))
CANDIDATE_K = int(os.getenv("CANDIDATE_K", "30"))
MIN_EXACT_OPERATION_EXAMPLES = int(
    os.getenv("MIN_EXACT_OPERATION_EXAMPLES", "2")
)
MAX_EXAMPLE_CHARS = int(os.getenv("MAX_EXAMPLE_CHARS", "600"))
MAX_OUTPUT_TOKENS = int(os.getenv("MAX_OUTPUT_TOKENS", "180"))
CONTEXT_SIZE = int(os.getenv("CONTEXT_SIZE", "3072"))
MAX_PROMPT_CHARS = int(os.getenv("MAX_PROMPT_CHARS", "9000"))
MAX_CONTEXT_CHARS = int(os.getenv("MAX_CONTEXT_CHARS", "2000"))
LLAMA_THREADS = int(os.getenv("LLAMA_THREADS", "3"))
LLAMA_BATCH_THREADS = int(os.getenv("LLAMA_BATCH_THREADS", "3"))
LLAMA_BATCH_SIZE = int(os.getenv("LLAMA_BATCH_SIZE", "128"))
EMBED_THREADS = int(os.getenv("EMBED_THREADS", "1"))
GPU_LAYERS = int(os.getenv("GPU_LAYERS", "0"))  # 0 = CPU only
RETRIEVAL_VERSION = "operation-aware-v3"

# Keep PyTorch/SentenceTransformer from consuming every VM CPU.
torch.set_num_threads(max(1, EMBED_THREADS))
try:
    torch.set_num_interop_threads(1)
except RuntimeError:
    pass

# ------------------------ Operation/risk definitions ---------------------

# Priority matters: more specific/destructive patterns should appear first.
OPERATION_PATTERNS: dict[str, tuple[str, ...]] = {
    "write_erase": (
        r"(?im)^\s*(?:write\s+erase|erase\s+startup-config)\s*$",
    ),
    "reload": (
        r"(?im)^\s*reload(?:\s+.*)?$",
    ),
    "remove_ospf_process": (
        r"(?im)^\s*no\s+router\s+ospf(?:\s+\S+)?\s*$",
    ),
    "remove_bgp_process": (
        r"(?im)^\s*no\s+router\s+bgp(?:\s+\S+)?\s*$",
    ),
    "remove_bgp_neighbor": (
        r"(?im)^\s*no\s+neighbor\s+\S+",
    ),
    "remove_default_route": (
        r"(?im)^\s*no\s+ip\s+route\s+0\.0\.0\.0\s+0\.0\.0\.0\b",
        r"(?im)^\s*no\s+ipv6\s+route\s+::/0\b",
    ),
    "interface_shutdown": (
        # "shutdown" must be a command line, not a word in topology prose.
        r"(?im)^\s*shutdown\s*$",
    ),
    "interface_enable": (
        r"(?im)^\s*no\s+shutdown\s*$",
    ),
    "remove_interface_ip": (
        r"(?im)^\s*no\s+ip\s+address(?:\s+.*)?$",
        r"(?im)^\s*no\s+ipv6\s+address(?:\s+.*)?$",
    ),
    "interface_ip_change": (
        r"(?im)^\s*ip\s+address\s+\S+\s+\S+",
        r"(?im)^\s*ipv6\s+address\s+\S+",
    ),
    "management_lockout": (
        r"(?im)^\s*no\s+transport\s+input\b",
        r"(?im)^\s*access-class\s+\S+\s+in\s*$",
        r"(?im)^\s*login\s+local\s*$",
    ),
    "permit_any_any": (
        r"(?im)^\s*permit\s+(?:ip\s+)?any\s+any\b",
    ),
    "acl_deny_any_inbound": (
        r"(?im)^\s*deny\s+(?:ip\s+)?any\s+any\b",
    ),
    "acl_apply_outbound": (
        r"(?im)^\s*ip\s+access-group\s+\S+\s+out\s*$",
    ),
    "remove_nat_overload": (
        r"(?im)^\s*no\s+ip\s+nat\s+inside\s+source\b.*\boverload\b",
    ),
    "nat_add": (
        r"(?im)^\s*ip\s+nat\s+inside\s+source\b",
    ),
    "remove_vlan": (
        r"(?im)^\s*no\s+vlan\s+\d+\s*$",
    ),
    "vlan_add": (
        r"(?im)^\s*vlan\s+\d+\s*$",
    ),
    "trunk_allowed_vlan_change": (
        r"(?im)^\s*switchport\s+trunk\s+allowed\s+vlan\b",
    ),
    "passive_interface_change": (
        r"(?im)^\s*(?:no\s+)?passive-interface\b",
    ),
    "ospf_cost_change": (
        r"(?im)^\s*ip\s+ospf\s+cost\s+\d+\s*$",
    ),
    "ospf_network_add": (
        r"(?im)^\s*network\s+\S+\s+\S+\s+area\s+\S+",
    ),
    "bgp_neighbor_add": (
        r"(?im)^\s*neighbor\s+\S+\s+remote-as\s+\d+",
    ),
    "bgp_network_add": (
        r"(?im)^\s*network\s+\S+(?:\s+mask\s+\S+)?\s*$",
    ),
    "static_route_add": (
        r"(?im)^\s*ip\s+route\s+\S+\s+\S+\s+\S+",
        r"(?im)^\s*ipv6\s+route\s+\S+\s+\S+",
    ),
    "qos_service_policy": (
        r"(?im)^\s*service-policy\s+(?:input|output)\s+\S+",
    ),
    "vty_access_change": (
        r"(?im)^\s*transport\s+input\b",
        r"(?im)^\s*access-class\b",
    ),
    "snmp_community_change": (
        r"(?im)^\s*(?:no\s+)?snmp-server\s+community\b",
    ),
    "ntp_server": (
        r"(?im)^\s*(?:no\s+)?ntp\s+server\b",
    ),
    "logging_host": (
        r"(?im)^\s*(?:no\s+)?logging\s+(?:host\s+)?\S+",
    ),
    "banner_change": (
        r"(?im)^\s*(?:no\s+)?banner\s+\S+",
    ),
    "interface_description": (
        r"(?im)^\s*(?:no\s+)?description(?:\s+.*)?$",
    ),
    "add_loopback_not_advertised": (
        r"(?im)^\s*interface\s+loopback\d+\s*$",
    ),
}

# Dataset category names mapped to canonical operation names.
CATEGORY_TO_OPERATION: dict[str, str] = {
    "interface_shutdown_critical": "interface_shutdown",
}

# Minimum score is a safety floor, not the final score.
RISK_FLOORS: dict[str, int] = {
    "write_erase": 95,
    "reload": 75,
    "remove_ospf_process": 85,
    "remove_bgp_process": 85,
    "remove_bgp_neighbor": 60,
    "remove_default_route": 70,
    "interface_shutdown": 55,
    "remove_interface_ip": 50,
    "interface_ip_change": 35,
    "management_lockout": 75,
    "permit_any_any": 65,
    "acl_deny_any_inbound": 55,
    "remove_nat_overload": 55,
    "remove_vlan": 50,
    "trunk_allowed_vlan_change": 40,
    "passive_interface_change": 35,
    "bgp_neighbor_add": 40,
    "static_route_add": 30,
    "qos_service_policy": 25,
    "vty_access_change": 35,
    "snmp_community_change": 30,
    "interface_description": 0,
    "banner_change": 0,
    "ntp_server": 5,
    "logging_host": 5,
}

DESTRUCTIVE_OPERATIONS = {
    "write_erase",
    "reload",
    "remove_ospf_process",
    "remove_bgp_process",
    "remove_bgp_neighbor",
    "remove_default_route",
    "interface_shutdown",
    "remove_interface_ip",
    "management_lockout",
    "remove_nat_overload",
    "remove_vlan",
}

JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "risk_level": {
            "type": "string",
            "enum": ["low", "medium", "high", "critical"],
        },
        "affected_areas": {
            "type": "array",
            "items": {"type": "string"},
        },
        "reason": {"type": "string"},
        "recommended_action": {"type": "string"},
    },
    "required": [
        "risk_score",
        "risk_level",
        "affected_areas",
        "reason",
        "recommended_action",
    ],
    "additionalProperties": False,
}


@dataclass(frozen=True)
class Sample:
    """Store one normalized training example used by the retrieval system.
    
    The dataclass keeps the original prompt/output along with the extracted proposed
    change and detected operation labels so the data can be cached and reconstructed."""
    sample_id: str
    category: str
    risk_level: str
    risk_score: int
    input_text: str
    output_text: str
    proposed_change: str
    operations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Convert the sample into JSON-serializable data for the cache file."""
        return {
            "sample_id": self.sample_id,
            "category": self.category,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "input_text": self.input_text,
            "output_text": self.output_text,
            "proposed_change": self.proposed_change,
            "operations": list(self.operations),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Sample":
        """Rebuild a Sample object from a cached dictionary."""
        return cls(
            sample_id=str(value["sample_id"]),
            category=str(value["category"]),
            risk_level=str(value["risk_level"]),
            risk_score=int(value["risk_score"]),
            input_text=str(value["input_text"]),
            output_text=str(value["output_text"]),
            proposed_change=str(value["proposed_change"]),
            operations=tuple(value.get("operations", [])),
        )


class NetworkRiskAnalyzer:
    """Coordinate dataset loading, vector retrieval, Qwen inference, and validation.
    
    Initialization is split so retrieval-only testing can run without loading the
    larger GGUF language model."""
    def __init__(
        self,
        dataset_path: Path = DATASET_PATH,
        model_path: Path = MODEL_PATH,
        cache_dir: Path = CACHE_DIR,
    ) -> None:
        """Store file locations and initialize model/index references as unloaded."""
        self.dataset_path = dataset_path
        self.model_path = model_path
        self.cache_dir = cache_dir

        self.samples: list[Sample] = []
        self.embedder: SentenceTransformer | None = None
        self.index: faiss.Index | None = None
        self.llm: Llama | None = None

    def initialize(self, load_llm: bool = True) -> None:
        """Load the embedding model and FAISS index, and optionally load Qwen."""
        if not self.dataset_path.is_file():
            raise FileNotFoundError(f"Dataset not found: {self.dataset_path}")

        self.cache_dir.mkdir(parents=True, exist_ok=True)

        LOGGER.info("Loading embedding model: %s", EMBED_MODEL)
        self.embedder = SentenceTransformer(EMBED_MODEL, device="cpu")

        self._load_or_build_index()

        if load_llm:
            self._load_llm()

    def _load_llm(self) -> None:
        """Load the quantized GGUF model with CPU/GPU settings from environment variables."""
        if not self.model_path.is_file():
            raise FileNotFoundError(
                f"GGUF model not found: {self.model_path}\n"
                "Run download_model.py or set MODEL_PATH."
            )

        LOGGER.info("Loading GGUF model: %s", self.model_path)
        self.llm = Llama(
            model_path=str(self.model_path),
            n_ctx=CONTEXT_SIZE,
            n_threads=LLAMA_THREADS,
            n_threads_batch=LLAMA_BATCH_THREADS,
            n_batch=LLAMA_BATCH_SIZE,
            n_gpu_layers=GPU_LAYERS,
            use_mmap=True,
            use_mlock=False,
            logits_all=False,
            verbose=False,
        )

    def _cache_signature(self) -> str:
        """Create a short fingerprint for the dataset and retrieval configuration.
        
        A changed dataset, embedding model, or retrieval version produces a new cache
        name and forces the index to be rebuilt automatically."""
        digest = hashlib.sha256()
        with self.dataset_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(EMBED_MODEL.encode("utf-8"))
        digest.update(RETRIEVAL_VERSION.encode("utf-8"))
        return digest.hexdigest()[:20]

    def _load_or_build_index(self) -> None:
        """Load a valid FAISS cache or build and persist a new vector index.
        
        Each sample is embedded once. Future runs reuse the saved FAISS index and
        normalized sample metadata unless the cache signature changes."""
        signature = self._cache_signature()
        index_path = self.cache_dir / f"index-{signature}.faiss"
        samples_path = self.cache_dir / f"samples-{signature}.json"

        if index_path.is_file() and samples_path.is_file():
            LOGGER.info("Loading cached FAISS index: %s", index_path)
            self.index = faiss.read_index(str(index_path))
            with samples_path.open("r", encoding="utf-8") as handle:
                self.samples = [
                    Sample.from_dict(item) for item in json.load(handle)
                ]

            if self.index.ntotal != len(self.samples):
                raise RuntimeError(
                    "Cached index/sample count mismatch. Delete .rag_cache and retry."
                )
            return

        LOGGER.info("No valid cache found; parsing dataset and building index once.")
        self.samples = load_dataset(self.dataset_path)
        retrieval_texts = [build_sample_retrieval_text(s) for s in self.samples]

        assert self.embedder is not None
        embeddings = self.embedder.encode(
            retrieval_texts,
            batch_size=32,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=True,
        ).astype("float32")

        self.index = faiss.IndexFlatIP(embeddings.shape[1])
        self.index.add(embeddings)

        faiss.write_index(self.index, str(index_path))
        with samples_path.open("w", encoding="utf-8") as handle:
            json.dump(
                [sample.to_dict() for sample in self.samples],
                handle,
                ensure_ascii=False,
            )

        # Remove obsolete versions so caches do not accumulate.
        for old_path in self.cache_dir.glob("index-*.faiss"):
            if old_path != index_path:
                old_path.unlink(missing_ok=True)
        for old_path in self.cache_dir.glob("samples-*.json"):
            if old_path != samples_path:
                old_path.unlink(missing_ok=True)

        LOGGER.info("Saved FAISS cache with %d samples.", len(self.samples))

    def retrieve_examples(
        self, user_config: str, top_k: int = TOP_K
    ) -> list[dict[str, Any]]:
        """Retrieve and rerank examples that best match the submitted change.
        
        FAISS supplies semantic candidates. Operation overlap, exact primary operation
        matches, and destructive-operation matches then influence the final ranking."""
        if self.embedder is None or self.index is None:
            raise RuntimeError("Analyzer is not initialized.")

        proposed_change = extract_proposed_change(user_config)
        query_operations = detect_operations(proposed_change)
        query_text = build_query_retrieval_text(
            proposed_change, query_operations
        )

        query_embedding = self.embedder.encode(
            [query_text],
            convert_to_numpy=True,
            normalize_embeddings=True,
        ).astype("float32")

        candidate_count = min(max(CANDIDATE_K, top_k), len(self.samples))
        semantic_scores, ids = self.index.search(
            query_embedding, candidate_count
        )

        candidates: list[dict[str, Any]] = []
        query_set = set(query_operations)

        for semantic_score, idx in zip(semantic_scores[0], ids[0]):
            if idx < 0:
                continue

            sample = self.samples[int(idx)]
            sample_set = set(sample.operations)
            overlap = query_set & sample_set

            operation_score = jaccard(query_set, sample_set)
            exact_primary = bool(
                query_operations
                and sample.operations
                and query_operations[0] == sample.operations[0]
            )
            destructive_match = bool(overlap & DESTRUCTIVE_OPERATIONS)

            # Semantic similarity still matters, but operation identity dominates.
            combined_score = (
                0.50 * float(semantic_score)
                + 0.35 * operation_score
                + (0.20 if exact_primary else 0.0)
                + (0.20 if destructive_match else 0.0)
            )

            candidates.append(
                {
                    "sample": sample,
                    "semantic_similarity": float(semantic_score),
                    "operation_similarity": operation_score,
                    "combined_score": combined_score,
                    "exact_operation_match": bool(overlap),
                    "exact_primary_match": exact_primary,
                }
            )

        candidates.sort(
            key=lambda item: (
                item["exact_primary_match"],
                item["exact_operation_match"],
                item["combined_score"],
            ),
            reverse=True,
        )

        selected = select_candidates(
            candidates=candidates,
            query_operations=query_operations,
            top_k=top_k,
        )

        return [
            {
                "similarity": round(item["semantic_similarity"], 3),
                "operation_similarity": round(
                    item["operation_similarity"], 3
                ),
                "combined_score": round(item["combined_score"], 3),
                "sample_id": item["sample"].sample_id,
                "category": item["sample"].category,
                "operations": list(item["sample"].operations),
                "risk_level": canonical_risk_level(
                    item["sample"].risk_score
                ),
                "risk_score": item["sample"].risk_score,
                "input_text": item["sample"].input_text,
                "proposed_change": item["sample"].proposed_change,
                "output_text": item["sample"].output_text,
            }
            for item in selected
        ]

    def analyze_config(self, user_config: str) -> dict[str, Any]:
        """Run the complete risk-analysis pipeline for one configuration change."""
        if self.llm is None:
            raise RuntimeError("LLM is not loaded.")

        proposed_change = extract_proposed_change(user_config)
        operations = detect_operations(proposed_change)
        risk_floor = deterministic_risk_floor(operations)
        retrieved = self.retrieve_examples(user_config)
        prompt = build_prompt(
            user_config=user_config,
            proposed_change=proposed_change,
            operations=operations,
            risk_floor=risk_floor,
            retrieved_examples=retrieved,
        )

        raw = self._generate_json(prompt)
        assessment = validate_and_enforce_assessment(
            raw=raw,
            operations=operations,
            risk_floor=risk_floor,
        )

        return {
            "assessment": assessment,
            "detected_operations": operations,
            "deterministic_risk_floor": risk_floor,
            "retrieved_examples": retrieved,
        }

    def _generate_json(self, prompt: str) -> str:
        """Send the constructed prompt to Qwen and return its JSON response text."""
        assert self.llm is not None

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a network configuration risk analysis assistant. "
                    "Return exactly one valid JSON object. Do not expose chain "
                    "of thought, use markdown, or add text outside the JSON."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        kwargs: dict[str, Any] = {
            "messages": messages,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "temperature": 0.0,
            "top_p": 1.0,
            "repeat_penalty": 1.05,
        }

        # Recent llama-cpp-python versions support JSON-schema-constrained output.
        # Fall back to unconstrained chat completion for older builds.
        try:
            result = self.llm.create_chat_completion(
                **kwargs,
                response_format={
                    "type": "json_object",
                    "schema": JSON_SCHEMA,
                },
            )
        except (TypeError, ValueError):
            LOGGER.warning(
                "Installed llama-cpp-python lacks schema response_format; "
                "using prompt-only JSON generation."
            )
            result = self.llm.create_chat_completion(**kwargs)

        content = result["choices"][0]["message"]["content"]
        return extract_json_object(str(content))


def load_dataset(path: Path) -> list[Sample]:
    """Parse the JSONL dataset into normalized Sample objects.
    
    The loader extracts user/assistant messages, isolates the proposed change, and
    adds both regex-detected and category-derived operation labels."""
    loaded: list[Sample] = []

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                messages = item["messages"]
                input_text = find_message_content(messages, "user")
                output_text = find_message_content(messages, "assistant")
                category = str(item["category"])
                proposed_change = extract_proposed_change(input_text)

                detected = detect_operations(proposed_change)
                category_operation = CATEGORY_TO_OPERATION.get(
                    category, category
                )
                if category_operation not in detected:
                    detected.insert(0, category_operation)

                loaded.append(
                    Sample(
                        sample_id=str(item["sample_id"]),
                        category=category,
                        risk_level=str(item.get("risk_level", "")),
                        risk_score=int(item["risk_score"]),
                        input_text=input_text,
                        output_text=output_text,
                        proposed_change=proposed_change,
                        operations=tuple(unique_preserving_order(detected)),
                    )
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError(
                    f"Invalid JSONL record on line {line_number}: {exc}"
                ) from exc

    if not loaded:
        raise ValueError("The dataset contains no usable samples.")
    return loaded


def find_message_content(messages: Iterable[dict[str, Any]], role: str) -> str:
    """Return the content of the first chat message with the requested role."""
    for message in messages:
        if message.get("role") == role:
            return str(message.get("content", ""))
    raise KeyError(f"No {role!r} message found")


def extract_proposed_change(text: str) -> str:
    """
    Extract only the Proposed Change section when present.

    This prevents Current Configuration lines such as "no shutdown" or an old
    description from dominating retrieval for a different proposed operation.
    Raw pasted configurations are returned unchanged.
    """
    match = re.search(
        r"(?is)\bProposed\s+Change\s*:\s*(.*?)(?=\n\s*[A-Z][A-Za-z ]+\s*:\s*|\Z)",
        text,
    )
    if match:
        extracted = match.group(1).strip()
        if extracted:
            return extracted
    return text.strip()


def detect_operations(config: str) -> list[str]:
    """Identify known network-change operations by applying the regex rule table."""
    operations: list[str] = []
    for operation, patterns in OPERATION_PATTERNS.items():
        if any(re.search(pattern, config) for pattern in patterns):
            operations.append(operation)
    return unique_preserving_order(operations) or ["other"]


def unique_preserving_order(values: Iterable[str]) -> list[str]:
    """Remove duplicates while retaining the original order of the values."""
    return list(dict.fromkeys(values))


def build_sample_retrieval_text(sample: Sample) -> str:
    # Operation labels are repeated intentionally to give them more embedding
    # weight without making the prompt larger.
    """Create the normalized text embedded for a stored dataset sample."""
    op_text = " ".join(sample.operations)
    return (
        f"operation {op_text}\n"
        f"network change type {op_text}\n"
        f"category {sample.category}\n"
        f"proposed configuration:\n{sample.proposed_change}"
    )


def build_query_retrieval_text(
    proposed_change: str, operations: list[str]
) -> str:
    """Create query text in the same format used for stored sample embeddings."""
    op_text = " ".join(operations)
    return (
        f"operation {op_text}\n"
        f"network change type {op_text}\n"
        f"proposed configuration:\n{proposed_change}"
    )


def jaccard(left: set[str], right: set[str]) -> float:
    """Return Jaccard similarity between two operation sets in the range 0 to 1."""
    if not left or not right:
        return 0.0
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def select_candidates(
    candidates: list[dict[str, Any]],
    query_operations: list[str],
    top_k: int,
) -> list[dict[str, Any]]:
    """
    Guarantee operation-matched examples first, then fill by hybrid score.

    Duplicate sample IDs are prevented. A category cap reduces repetitive
    examples while still allowing multiple exact matches for destructive ops.
    """
    if not candidates:
        return []

    query_set = set(query_operations)
    exact = [
        c
        for c in candidates
        if query_set & set(c["sample"].operations)
    ]
    remaining = [c for c in candidates if c not in exact]

    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    category_counts: dict[str, int] = {}

    required_exact = min(
        MIN_EXACT_OPERATION_EXAMPLES,
        top_k,
        len(exact),
    )

    def add(candidate: dict[str, Any], enforce_cap: bool) -> bool:
        """Add one candidate unless it is duplicated or violates the category cap."""
        sample: Sample = candidate["sample"]
        if sample.sample_id in selected_ids:
            return False
        if enforce_cap and category_counts.get(sample.category, 0) >= 2:
            return False
        selected.append(candidate)
        selected_ids.add(sample.sample_id)
        category_counts[sample.category] = (
            category_counts.get(sample.category, 0) + 1
        )
        return True

    for candidate in exact:
        if len(selected) >= required_exact:
            break
        add(candidate, enforce_cap=False)

    for candidate in exact + remaining:
        if len(selected) >= top_k:
            break
        add(candidate, enforce_cap=True)

    # If the diversity cap left empty slots, fill them without the cap.
    for candidate in candidates:
        if len(selected) >= top_k:
            break
        add(candidate, enforce_cap=False)

    return selected


def deterministic_risk_floor(operations: Iterable[str]) -> int:
    """Return the highest mandatory minimum score for the detected operations."""
    return max((RISK_FLOORS.get(op, 0) for op in operations), default=0)


def canonical_risk_level(score: int) -> str:
    # Matches the user's stated scale.
    """Convert a numeric score into the project's four canonical risk levels."""
    if score <= 20:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 80:
        return "high"
    return "critical"


def compact_expected_output(output_text: str) -> str:
    """Shrink a dataset answer before inserting it into the model prompt."""
    try:
        value = json.loads(output_text)
        score = int(value.get("risk_score", 0))
        compact = {
            "risk_score": score,
            # Canonicalize inconsistent dataset labels such as medium-high and
            # high for scores above 80.
            "risk_level": canonical_risk_level(score),
            "affected_areas": value.get("affected_areas", []),
            "reason": value.get("reason", ""),
            "recommended_action": value.get(
                "recommended_action", "manual_review"
            ),
        }
        return json.dumps(compact, separators=(",", ":"))
    except (json.JSONDecodeError, TypeError, ValueError):
        return output_text[:600]


def build_prompt(
    user_config: str,
    proposed_change: str,
    operations: list[str],
    risk_floor: int,
    retrieved_examples: list[dict[str, Any]],
) -> str:
    """Assemble instructions, retrieved examples, context, and schema for Qwen."""
    example_blocks: list[str] = []

    for number, example in enumerate(retrieved_examples, start=1):
        compact_input = example["proposed_change"][:MAX_EXAMPLE_CHARS]
        example_blocks.append(
            f"Example {number}\n"
            f"Operations: {', '.join(example['operations'])}\n"
            f"Configuration:\n{compact_input}\n"
            f"Assessment: {compact_expected_output(example['output_text'])}"
        )

    examples_text = "\n\n".join(example_blocks) or "No examples available."

    # Keep context bounded so the prompt stays within the LLM window.
    context = user_config[-MAX_CONTEXT_CHARS:]
    if len(context) > MAX_CONTEXT_CHARS:
        context = context[-MAX_CONTEXT_CHARS:]

    prompt = f"""Analyze the proposed network configuration change.

Scoring scale:
0-20 low
21-50 medium
51-80 high
81-100 critical

Detected operations: {', '.join(operations)}
Deterministic minimum score: {risk_floor}

The final score MUST NOT be lower than {risk_floor}. Account for device role,
topology context, blast radius, loss of connectivity, management lockout,
routing disruption, security exposure, and rollback difficulty. Retrieved
examples are guidance, not rules.

Retrieved examples:
{examples_text}

Input context:
{context}

Proposed change being evaluated:
{proposed_change}

Return exactly one JSON object matching this schema:
{json.dumps(JSON_SCHEMA, separators=(",", ":"))}
"""

    if len(prompt) > MAX_PROMPT_CHARS:
        overflow = len(prompt) - MAX_PROMPT_CHARS
        context = context[overflow:] if overflow < len(context) else context[-MAX_CONTEXT_CHARS:]
        prompt = f"""Analyze the proposed network configuration change.

Scoring scale:
0-20 low
21-50 medium
51-80 high
81-100 critical

Detected operations: {', '.join(operations)}
Deterministic minimum score: {risk_floor}

The final score MUST NOT be lower than {risk_floor}. Account for device role,
topology context, blast radius, loss of connectivity, management lockout,
routing disruption, security exposure, and rollback difficulty. Retrieved
examples are guidance, not rules.

Retrieved examples:
{examples_text}

Input context:
{context}

Proposed change being evaluated:
{proposed_change}

Return exactly one JSON object matching this schema:
{json.dumps(JSON_SCHEMA, separators=(",", ":"))}
"""


def extract_json_object(text: str) -> str:
    """Remove non-JSON text and return the outermost JSON object substring."""
    text = text.replace("<think>", "").replace("</think>", "").strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError(f"Model did not return a JSON object: {text[:300]}")
    return text[start : end + 1]


def validate_and_enforce_assessment(
    raw: str,
    operations: list[str],
    risk_floor: int,
) -> dict[str, Any]:
    """Validate model output and apply deterministic safety rules.
    
    The final score is clamped to 0-100 and cannot fall below the operation-based
    risk floor. Destructive high-risk changes are also prevented from being
    automatically approved."""
    try:
        assessment = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Model returned invalid JSON: {raw}") from exc

    required = set(JSON_SCHEMA["required"])
    missing = required - set(assessment)
    if missing:
        raise ValueError(f"Model response is missing fields: {sorted(missing)}")

    try:
        model_score = int(assessment["risk_score"])
    except (TypeError, ValueError) as exc:
        raise ValueError("risk_score must be an integer") from exc

    enforced_score = max(0, min(100, max(model_score, risk_floor)))
    assessment["risk_score"] = enforced_score
    assessment["risk_level"] = canonical_risk_level(enforced_score)

    affected = assessment.get("affected_areas")
    if not isinstance(affected, list):
        affected = [str(affected)]
    assessment["affected_areas"] = [
        str(value) for value in affected if str(value).strip()
    ]

    assessment["reason"] = str(assessment.get("reason", "")).strip()
    assessment["recommended_action"] = str(
        assessment.get("recommended_action", "manual_review")
    ).strip()

    # Ensure destructive operations never produce an accidental approval.
    if set(operations) & DESTRUCTIVE_OPERATIONS and enforced_score >= 51:
        if assessment["recommended_action"].lower() in {
            "approve",
            "auto_approve",
            "proceed",
        }:
            assessment["recommended_action"] = (
                "manual_review_and_approval_required"
            )

    assessment["model_risk_score"] = max(0, min(100, model_score))
    assessment["final_risk_score"] = enforced_score
    assessment["deterministic_floor_applied"] = model_score < risk_floor
    return assessment


def build_scoring_engine_record(
    output: dict[str, Any],
    user_config: str,
    model_path: Path,
    include_config: bool = False,
) -> dict[str, Any]:
    """Build a compact, stable record for a downstream scoring engine.

    The record intentionally excludes full retrieved examples and the complete
    configuration by default, which reduces file size and avoids unnecessarily
    exposing device configuration. Set include_config=True when the downstream
    engine explicitly requires the submitted configuration.
    """
    assessment = output["assessment"]
    operations = [str(op) for op in output.get("detected_operations", [])]
    destructive = sorted(set(operations) & DESTRUCTIVE_OPERATIONS)
    final_score = int(assessment["risk_score"])
    model_score = int(assessment.get("model_risk_score", final_score))
    risk_floor = int(output.get("deterministic_risk_floor", 0))

    # Conservative decision fields make integration easier for a policy/scoring
    # engine while keeping the numeric score as the source of truth.
    approval_required = bool(final_score >= 51 or destructive)
    auto_approval_allowed = bool(final_score <= 20 and not destructive)

    evidence = []
    for example in output.get("retrieved_examples", []):
        evidence.append(
            {
                "sample_id": example.get("sample_id"),
                "category": example.get("category"),
                "sample_risk_score": example.get("risk_score"),
                "sample_risk_level": example.get("risk_level"),
                "operations": example.get("operations", []),
                "semantic_similarity": example.get("similarity"),
                "operation_similarity": example.get("operation_similarity"),
                "combined_score": example.get("combined_score"),
            }
        )

    record: dict[str, Any] = {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "assessment_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_sha256": hashlib.sha256(
            user_config.encode("utf-8")
        ).hexdigest(),
        "risk": {
            "score": final_score,
            "level": assessment["risk_level"],
            "model_score": model_score,
            "deterministic_floor": risk_floor,
            "deterministic_floor_applied": bool(
                assessment.get("deterministic_floor_applied", False)
            ),
            "score_source": (
                "deterministic_floor"
                if assessment.get("deterministic_floor_applied", False)
                else "model"
            ),
        },
        "decision": {
            "approval_required": approval_required,
            "auto_approval_allowed": auto_approval_allowed,
            "recommended_action": assessment.get(
                "recommended_action", "manual_review"
            ),
        },
        "change": {
            "detected_operations": operations,
            "destructive_operations": destructive,
            "affected_areas": assessment.get("affected_areas", []),
        },
        "reason": assessment.get("reason", ""),
        "retrieval_evidence": evidence,
        "engine_metadata": {
            "model_file": model_path.name,
            "embedding_model": EMBED_MODEL,
            "retrieval_version": RETRIEVAL_VERSION,
            "top_k": TOP_K,
        },
    }

    if include_config:
        record["input_configuration"] = user_config

    return record


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    """Atomically write JSON so consumers never read a partial file."""
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")

    try:
        with temporary_path.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def read_multiline_config() -> str:
    """Read configuration text from standard input until END appears alone."""
    print("Paste the configuration. Type END on a new line when finished.\n")
    lines: list[str] = []
    for line in sys.stdin:
        if line.strip().upper() == "END":
            break
        lines.append(line.rstrip("\n"))
    return "\n".join(lines).strip()


def parse_args() -> argparse.Namespace:
    """Define and parse command-line options for models, retrieval, and output."""
    parser = argparse.ArgumentParser(
        description="Qwen GGUF network configuration risk analyzer"
    )
    parser.add_argument("--dataset", type=Path, default=DATASET_PATH)
    parser.add_argument("--model", type=Path, default=MODEL_PATH)
    parser.add_argument(
        "--config-file",
        type=Path,
        help="Read the configuration/context from a file instead of stdin.",
    )
    parser.add_argument(
        "--retrieval-only",
        action="store_true",
        help="Test operation detection and retrieval without loading Qwen.",
    )
    parser.add_argument(
        "--rebuild-index",
        action="store_true",
        help="Delete cached FAISS files before initialization.",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=OUTPUT_PATH,
        help=(
            "Write a compact scoring-engine JSON record to this path "
            f"(default: {OUTPUT_PATH})."
        ),
    )
    parser.add_argument(
        "--no-output-file",
        action="store_true",
        help="Do not write the scoring-engine JSON output file.",
    )
    parser.add_argument(
        "--include-config-in-output",
        action="store_true",
        help=(
            "Include the submitted configuration in the output file. "
            "Disabled by default to reduce file size and exposure."
        ),
    )
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


def main() -> int:
    """Run initialization, input collection, analysis, optional export, and display."""
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    cache_dir = CACHE_DIR
    if args.rebuild_index and cache_dir.exists():
        for path in cache_dir.glob("*"):
            if path.is_file():
                path.unlink()

    analyzer = NetworkRiskAnalyzer(
        dataset_path=args.dataset,
        model_path=args.model,
        cache_dir=cache_dir,
    )
    analyzer.initialize(load_llm=not args.retrieval_only)

    if args.config_file:
        user_config = args.config_file.read_text(encoding="utf-8").strip()
    else:
        user_config = read_multiline_config()

    if not user_config:
        LOGGER.error("No configuration entered.")
        return 2

    if args.retrieval_only:
        proposed = extract_proposed_change(user_config)
        operations = detect_operations(proposed)
        output = {
            "detected_operations": operations,
            "deterministic_risk_floor": deterministic_risk_floor(operations),
            "retrieved_examples": analyzer.retrieve_examples(user_config),
        }
    else:
        output = analyzer.analyze_config(user_config)

        if not args.no_output_file:
            scoring_record = build_scoring_engine_record(
                output=output,
                user_config=user_config,
                model_path=args.model,
                include_config=args.include_config_in_output,
            )
            write_json_atomic(args.output_file, scoring_record)
            LOGGER.info(
                "Scoring-engine output written to: %s",
                args.output_file.expanduser().resolve(),
            )

    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
