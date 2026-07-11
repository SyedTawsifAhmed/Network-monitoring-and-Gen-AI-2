from __future__ import annotations

import argparse
from pathlib import Path

from huggingface_hub import hf_hub_download


MODEL_OPTIONS = {
    "1.7b-q8": {
        "repo_id": "Qwen/Qwen3-1.7B-GGUF",
        "filename": "Qwen3-1.7B-Q8_0.gguf",
        "local_filename": "Qwen3-1.7B-Q8_0.gguf",
    },
    "8b-q4": {
        "repo_id": "Qwen/Qwen3-8B-GGUF",
        "filename": "Qwen3-8B-Q4_K_M.gguf",
        "local_filename": "Qwen3-8B-Q4_K_M.gguf",
    },
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download a Qwen3 GGUF model."
    )

    parser.add_argument(
        "--model",
        choices=MODEL_OPTIONS.keys(),
        default="8b-q4",
        help="Model variant to download",
    )

    parser.add_argument(
        "--output-dir",
        default="models",
        help="Directory in which the GGUF model will be stored",
    )

    args = parser.parse_args()

    model_info = MODEL_OPTIONS[args.model]
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Downloading {args.model}...")
    print(f"Repository: {model_info['repo_id']}")
    print(f"Filename: {model_info['filename']}")

    downloaded_path = hf_hub_download(
        repo_id=model_info["repo_id"],
        filename=model_info["filename"],
        local_dir=str(output_dir),
    )

    downloaded_path = Path(downloaded_path)
    expected_path = output_dir / model_info["local_filename"]

    if downloaded_path.resolve() != expected_path.resolve():
        downloaded_path.replace(expected_path)

    print("\nDownload completed.")
    print(f"Model path: {expected_path.resolve()}")
    print("\nSet the model path with:")
    print(f'export MODEL_PATH="{expected_path}"')


if __name__ == "__main__":
    main()