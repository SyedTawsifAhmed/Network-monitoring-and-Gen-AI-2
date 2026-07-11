import json
import faiss
import numpy as np
import torch
from sentence_transformers import SentenceTransformer
from transformers import AutoTokenizer, AutoModelForCausalLM


DATASET_PATH = "all_samples_with_metadata.jsonl"
QWEN_MODEL = "Qwen/Qwen3-1.7B"
EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
TOP_K = 5


samples = []
embedder = None
index = None
tokenizer = None
model = None


def load_dataset():
    loaded_samples = []

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        for line in f:
            item = json.loads(line)

            loaded_samples.append({
                "sample_id": item["sample_id"],
                "category": item["category"],
                "risk_level": item["risk_level"],
                "risk_score": item["risk_score"],
                "input_text": item["messages"][1]["content"],
                "output_text": item["messages"][2]["content"]
            })

    return loaded_samples


def initialize_rag():
    global samples, embedder, index, tokenizer, model

    print("Loading dataset...")
    samples = load_dataset()

    print("Loading embedding model...")
    embedder = SentenceTransformer(EMBED_MODEL)

    print("Building FAISS index...")
    texts = [sample["input_text"] for sample in samples]

    embeddings = embedder.encode(
        texts,
        convert_to_numpy=True,
        normalize_embeddings=True
    ).astype("float32")

    index = faiss.IndexFlatIP(embeddings.shape[1])
    index.add(embeddings)

    print("Loading Qwen model...")
    tokenizer = AutoTokenizer.from_pretrained(
        QWEN_MODEL,
        trust_remote_code=True
    )

    model = AutoModelForCausalLM.from_pretrained(
        QWEN_MODEL,
        dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True
    )

    print("RAG system ready.")


def retrieve_examples(user_config):
    query_embedding = embedder.encode(
        [user_config],
        convert_to_numpy=True,
        normalize_embeddings=True
    ).astype("float32")

    scores, ids = index.search(query_embedding, TOP_K)

    retrieved = []

    for score, idx in zip(scores[0], ids[0]):
        sample = samples[idx]

        retrieved.append({
            "similarity": round(float(score), 3),
            "sample_id": sample["sample_id"],
            "category": sample["category"],
            "risk_level": sample["risk_level"],
            "risk_score": sample["risk_score"],
            "input_text": sample["input_text"],
            "output_text": sample["output_text"]
        })

    return retrieved


def build_prompt(user_config, retrieved_examples):
    examples_text = ""

    for i, ex in enumerate(retrieved_examples, start=1):
        examples_text += f"""
Example {i}
Category: {ex["category"]}
Risk Level: {ex["risk_level"]}
Risk Score: {ex["risk_score"]}

Input:
{ex["input_text"]}

Expected Output:
{ex["output_text"]}
"""

    prompt = f"""
You are a network configuration risk analysis assistant.

Analyze the proposed network configuration change and return ONLY valid JSON.

Risk scoring:
0-20 = low
21-50 = medium
51-80 = high
81-100 = critical

Use these retrieved examples as guidance:

{examples_text}

Now analyze this new configuration:

{user_config}

Return ONLY JSON in this format:

{{
  "risk_score": 0,
  "risk_level": "low",
  "affected_areas": [],
  "reason": "",
  "recommended_action": ""
}}
"""

    return prompt


def generate_response(prompt):
    messages = [
        {
            "role": "system",
            "content": "You are a network configuration risk analysis assistant. Return only valid JSON."
        },
        {
            "role": "user",
            "content": prompt
        }
    ]

    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )

    inputs = tokenizer(text, return_tensors="pt").to(model.device)

    outputs = model.generate(
        **inputs,
        max_new_tokens=350,
        temperature=0.2,
        do_sample=True,
        pad_token_id=tokenizer.eos_token_id
    )

    generated_tokens = outputs[0][inputs["input_ids"].shape[-1]:]
    response = tokenizer.decode(generated_tokens, skip_special_tokens=True)

    return response.strip()


def analyze_config(user_config):
    retrieved = retrieve_examples(user_config)
    prompt = build_prompt(user_config, retrieved)
    result = generate_response(prompt)

    return {
        "assessment": result,
        "retrieved_examples": retrieved
    }