# Qwen Network Configuration Risk Dataset

This dataset contains 300 synthetic Cisco IOS-style configuration risk examples for Qwen fine-tuning or evaluation.

## Files

- `train.jsonl`: 208 samples
- `validation.jsonl`: 44 samples
- `test.jsonl`: 48 samples
- `all_samples_with_metadata.jsonl`: all samples with metadata preserved
- `metadata.csv`: sample-level metadata
- `labeling_guide.md`: explanation of labels and actions
- `generate_dataset.py`: generator script

## Risk Distribution

- Low: 75
- Medium: 75
- Medium-high: 75
- High: 75

## Purpose

The dataset teaches a model to map:

Cisco IOS proposed command(s) + current configuration + topology context + device role

to:

risk score + risk level + affected areas + reason + recommended action.

## Output schema

```json
{
  "risk_score": 90,
  "risk_level": "high",
  "affected_areas": ["interface", "routing", "connectivity"],
  "reason": "Short explanation of operational impact.",
  "recommended_action": "reject_or_senior_approval_required"
}
```

## Notes

This is synthetic data for a capstone prototype. Review samples and adjust scoring rules to match your final project topology, rubric, and source-of-truth model.
