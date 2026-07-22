from llama_cpp import Llama

llm = Llama(
    model_path="models/Qwen3-8B-Q4_K_M.gguf",
    n_ctx=4096,
    verbose=True,
)

tests = [
    "/no_think\n"
    "Return JSON only: {'number': 7}",
    "Return JSON only: {'number': 42}",
    "What is 2 + 2? Return JSON with key answer.",
]

for prompt in tests:
    result = llm.create_chat_completion(
        messages=[
            {"role": "user", "content": prompt}
        ],
        temperature=0.0,
        max_tokens=100,
    )

    print("PROMPT:", prompt)
    print("OUTPUT:", result["choices"][0]["message"]["content"])
    print()