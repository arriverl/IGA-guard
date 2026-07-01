#!/usr/bin/env python3
"""Fine-tune TinyBERT for WAF payload classification (optional GPU)."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

LABEL2ID = {
    "Normal": 0, "SQLi": 1, "XSS": 2, "CMD": 3,
    "PathTraversal": 4, "FileInclusion": 5, "XXE": 6, "PromptInjection": 7,
}


def load_csv(path: Path) -> tuple[list[str], list[int]]:
    texts, labels = [], []
    with path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            texts.append(row["payload"][:256])
            labels.append(LABEL2ID.get(row["label"], 0))
    return texts, labels


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default=str(ROOT / "data" / "samples" / "obfuscated_dataset.csv"))
    parser.add_argument("--model", default="prajjwal1/bert-tiny")
    parser.add_argument("--out", default=str(ROOT / "models" / "tinybert_waf"))
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--max-samples", type=int, default=None, help="限制训练样本数")
    args = parser.parse_args()

    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer, Trainer, TrainingArguments
        from torch.utils.data import Dataset
    except ImportError:
        print("Install: pip install torch transformers")
        print("Fallback: semantic branch uses keyword density without BERT.")
        sys.exit(0)

    texts, labels = load_csv(Path(args.data))
    if args.max_samples and len(texts) > args.max_samples:
        import random
        rng = random.Random(42)
        idx = list(range(len(texts)))
        rng.shuffle(idx)
        idx = idx[: args.max_samples]
        texts = [texts[i] for i in idx]
        labels = [labels[i] for i in idx]
        print(f"Subsampled to {len(texts)} for training")
    tok = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model, num_labels=len(LABEL2ID),
    )

    class DS(Dataset):
        def __init__(self, t, y):
            self.t, self.y = t, y
        def __len__(self):
            return len(self.t)
        def __getitem__(self, i):
            enc = tok(self.t[i], truncation=True, padding="max_length", max_length=128, return_tensors="pt")
            item = {k: v.squeeze(0) for k, v in enc.items()}
            item["labels"] = torch.tensor(self.y[i])
            return item

    ds = DS(texts, labels)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=str(out),
            num_train_epochs=args.epochs,
            per_device_train_batch_size=16,
            logging_steps=10,
            save_strategy="epoch",
            report_to="none",
        ),
        train_dataset=ds,
    )
    trainer.train()
    model.save_pretrained(str(out))
    tok.save_pretrained(str(out))
    print(f"TinyBERT saved -> {out}")
    print("Set configs/default.yaml: use_semantic_branch: true")


if __name__ == "__main__":
    main()
