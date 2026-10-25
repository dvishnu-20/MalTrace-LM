"""
Sequential Deep Learning & API Sequence Modeling (PyTorch BiLSTM with Attention).
Processes ordered sequences of Win32/Native API calls with self-attention mechanism,
producing family classification scores and interpretable attention weights per API transition.
"""

import json
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Union, Any
import numpy as np

import torch
import torch.nn as nn
import torch.nn.functional as F

from maltrace.contracts.schemas import NormalizedEvent


class APISequenceTokenizer:
    """
    Tokenizer converting sequences of API calls and event categories to token IDs.
    """

    def __init__(self, vocab: Optional[Dict[str, int]] = None):
        self.pad_token = "<PAD>"
        self.unk_token = "<UNK>"
        self.vocab: Dict[str, int] = vocab or {
            self.pad_token: 0,
            self.unk_token: 1
        }
        self.inv_vocab: Dict[int, str] = {v: k for k, v in self.vocab.items()}

    def fit_on_traces(self, traces_events: List[List[NormalizedEvent]]):
        """
        Build vocabulary from a corpus of trace events.
        """
        for events in traces_events:
            for ev in events:
                api = str(ev.api_name).lower().strip()
                cat = str(ev.category).lower().strip()
                token = f"{cat}::{api}"
                if token not in self.vocab:
                    idx = len(self.vocab)
                    self.vocab[token] = idx
                    self.inv_vocab[idx] = token

    def tokenize(self, events: List[NormalizedEvent], max_length: int = 128) -> Tuple[torch.Tensor, List[str]]:
        """
        Convert a list of NormalizedEvent into a padded LongTensor and token string list.
        """
        token_strs: List[str] = []
        token_ids: List[int] = []

        for ev in events:
            api = str(ev.api_name).lower().strip()
            cat = str(ev.category).lower().strip()
            t_str = f"{cat}::{api}"
            token_strs.append(t_str)
            token_ids.append(self.vocab.get(t_str, self.vocab[self.unk_token]))

        # Truncate or Pad
        if len(token_ids) > max_length:
            token_ids = token_ids[:max_length]
            token_strs = token_strs[:max_length]
        else:
            padding_len = max_length - len(token_ids)
            token_ids = token_ids + [self.vocab[self.pad_token]] * padding_len

        return torch.tensor(token_ids, dtype=torch.long), token_strs

    def save(self, filepath: Union[str, Path]):
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.vocab, f, indent=2)

    @classmethod
    def load(cls, filepath: Union[str, Path]) -> "APISequenceTokenizer":
        with open(filepath, "r", encoding="utf-8") as f:
            vocab = json.load(f)
        return cls(vocab=vocab)


class AttentionLayer(nn.Module):
    """
    Additive Self-Attention mechanism over BiLSTM hidden states.
    """

    def __init__(self, hidden_dim: int):
        super().__init__()
        self.projection = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.Tanh(),
            nn.Linear(hidden_dim // 2, 1, bias=False)
        )

    def forward(self, lstm_outputs: torch.Tensor, mask: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        lstm_outputs: (batch_size, seq_len, hidden_dim)
        mask: (batch_size, seq_len) True for valid tokens, False for padding
        Returns:
            context_vector: (batch_size, hidden_dim)
            attention_weights: (batch_size, seq_len)
        """
        # (batch_size, seq_len, 1)
        energy = self.projection(lstm_outputs)
        energy = energy.squeeze(-1)  # (batch_size, seq_len)

        if mask is not None:
            energy = energy.masked_fill(~mask, -1e9)

        attention_weights = F.softmax(energy, dim=-1)  # (batch_size, seq_len)
        # (batch_size, 1, seq_len) @ (batch_size, seq_len, hidden_dim) -> (batch_size, 1, hidden_dim)
        context = torch.bmm(attention_weights.unsqueeze(1), lstm_outputs).squeeze(1)

        return context, attention_weights


class APISequenceBiLSTM(nn.Module):
    """
    Bidirectional LSTM with Self-Attention for API sequence malware classification.
    """

    def __init__(
        self,
        vocab_size: int,
        num_classes: int,
        embed_dim: int = 64,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.2
    ):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.bilstm = nn.LSTM(
            input_size=embed_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0.0
        )
        self.attention = AttentionLayer(hidden_dim * 2)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes)
        )

    def forward(self, token_ids: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        token_ids: (batch_size, seq_len)
        Returns:
            logits: (batch_size, num_classes)
            attention_weights: (batch_size, seq_len)
        """
        mask = (token_ids != 0)
        embedded = self.embedding(token_ids)  # (B, L, E)
        lstm_out, _ = self.bilstm(embedded)   # (B, L, 2*H)
        context, attn_weights = self.attention(lstm_out, mask)
        logits = self.classifier(context)
        return logits, attn_weights


class SequenceInferenceEngine:
    """
    Production inference engine for evaluating API sequences with BiLSTM + Attention.
    """

    def __init__(
        self,
        model: APISequenceBiLSTM,
        tokenizer: APISequenceTokenizer,
        label_map: Dict[int, str]
    ):
        self.model = model
        self.tokenizer = tokenizer
        self.label_map = label_map
        self.model.eval()

    def predict_trace(self, events: List[NormalizedEvent], max_length: int = 64) -> Dict[str, Any]:
        """
        Evaluate normalized events and return predicted malware family and attention distribution.
        """
        if not events:
            return {
                "predicted_family": "Benign.Activity",
                "confidence": 0.50,
                "attention_highlights": []
            }

        tensor_seq, token_strs = self.tokenizer.tokenize(events, max_length=max_length)
        tensor_batch = tensor_seq.unsqueeze(0)  # (1, L)

        with torch.no_grad():
            logits, attn = self.model(tensor_batch)
            probs = F.softmax(logits, dim=-1).squeeze(0).numpy()
            attn_weights = attn.squeeze(0).numpy()

        pred_idx = int(np.argmax(probs))
        pred_label = self.label_map.get(pred_idx, "Threat.Generic")
        confidence = float(probs[pred_idx])

        # Pair events with their attention score
        highlights = []
        valid_len = min(len(events), len(token_strs))
        for i in range(valid_len):
            score = float(attn_weights[i])
            highlights.append({
                "event_id": events[i].event_id,
                "api_token": token_strs[i],
                "attention_weight": round(score, 4),
                "is_anchor": score > (1.5 / max(1, valid_len))
            })

        highlights.sort(key=lambda x: x["attention_weight"], reverse=True)

        return {
            "predicted_family": pred_label,
            "confidence": round(confidence, 4),
            "class_probabilities": {self.label_map[i]: round(float(p), 4) for i, p in enumerate(probs)},
            "attention_highlights": highlights[:5]  # Top 5 most influential API transitions
        }


def train_sequence_model(
    records: List[Any],
    output_path: Union[str, Path] = "models/sequence_model/bilstm_attention.pt",
    epochs: int = 15,
    lr: float = 0.005,
    seed: int = 42
) -> str:
    """
    Train PyTorch BiLSTM with Self-Attention on execution trace sequences and save weights.
    """
    import torch.optim as optim
    torch.manual_seed(seed)
    np.random.seed(seed)

    label_map = {
        0: "Benign.Activity",
        1: "Ransomware.Generic",
        2: "Stealer.Generic",
        3: "Trojan.Generic",
        4: "Dropper.Generic",
        5: "Wiper.Generic"
    }
    inv_label_map = {v: k for k, v in label_map.items()}

    # Build tokenizer vocabulary from records
    tok = APISequenceTokenizer()
    tok.fit_on_traces([rec.events for rec in records])

    model = APISequenceBiLSTM(
        vocab_size=len(tok.vocab) + 10,
        num_classes=len(label_map),
        embed_dim=32,
        hidden_dim=64,
        num_layers=1,
        dropout=0.1
    )
    optimizer = optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()

    model.train()
    for epoch in range(epochs):
        for rec in records:
            lbl_idx = 0
            if rec.label:
                for k, v in inv_label_map.items():
                    if k.split(".")[0].lower() in rec.label.lower():
                        lbl_idx = v
                        break

            tensor_seq, _ = tok.tokenize(rec.events, max_length=128)
            tensor_batch = tensor_seq.unsqueeze(0)
            target = torch.tensor([lbl_idx], dtype=torch.long)

            optimizer.zero_grad()
            logits, _ = model(tensor_batch)
            loss = criterion(logits, target)
            loss.backward()
            optimizer.step()

    out_p = Path(output_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    torch.save({
        "model_state_dict": model.state_dict(),
        "vocab": tok.vocab,
        "label_map": label_map
    }, str(out_p))

    return str(out_p)


def build_default_sequence_engine(
    weights_path: Optional[Union[str, Path]] = None
) -> SequenceInferenceEngine:
    """
    Factory function creating an initialized sequence model with canonical vocabulary
    and loading trained weights if available.
    """
    default_p = Path("models/sequence_model/bilstm_attention.pt")
    target_path = Path(weights_path) if weights_path else (default_p if default_p.exists() else None)

    if target_path and target_path.exists():
        checkpoint = torch.load(str(target_path), map_location="cpu")
        tok = APISequenceTokenizer()
        tok.vocab = checkpoint.get("vocab", {})
        tok.inv_vocab = {v: k for k, v in tok.vocab.items()}
        label_map = checkpoint.get("label_map", {0: "Benign.Activity", 1: "Threat.Generic"})

        model = APISequenceBiLSTM(
            vocab_size=len(tok.vocab) + 10,
            num_classes=len(label_map),
            embed_dim=32,
            hidden_dim=64,
            num_layers=1,
            dropout=0.1
        )
        model.load_state_dict(checkpoint["model_state_dict"])
        model.eval()
        return SequenceInferenceEngine(model, tok, label_map)

    # Fallback with canonical vocabulary
    common_apis = [
        "process::createprocess", "process::createprocessinternalw", "process::winexec",
        "file::ntcreatefile", "file::writefile", "file::readfile", "file::deletefilew",
        "registry::regsetvalueexw", "registry::ntsetvaluekey", "registry::regcreatekeyexw",
        "network::wsaconnect", "network::connect", "network::httpsendrequestw",
        "service::createservicew", "memory::virtualallocex", "memory::createremotethread",
        "memory::writeprocessmemory", "synchronization::createmutexw"
    ]
    tok = APISequenceTokenizer()
    for token in common_apis:
        idx = len(tok.vocab)
        tok.vocab[token] = idx
        tok.inv_vocab[idx] = token

    label_map = {
        0: "Benign.Activity",
        1: "Ransomware.Generic",
        2: "Stealer.Generic",
        3: "Trojan.Generic",
        4: "Dropper.Generic",
        5: "Wiper.Generic"
    }

    model = APISequenceBiLSTM(
        vocab_size=len(tok.vocab) + 10,
        num_classes=len(label_map),
        embed_dim=32,
        hidden_dim=64,
        num_layers=1,
        dropout=0.1
    )
    model.eval()

    return SequenceInferenceEngine(model, tok, label_map)
