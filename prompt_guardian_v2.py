#!/usr/bin/env python3
"""
PromptGuardian v2 — Defense in Depth
Auteur : généré pour Pyer
Usage  : python prompt_guardian_v2.py --prompt "..." [--endpoint ollama_qwen]
         python prompt_guardian_v2.py --file prompt.txt --endpoint mistral_api
"""

#import re
import regex as re
import json
import yaml
import logging
import argparse
import hashlib
import datetime
import os
import sys
import time
import unicodedata
import math
import urllib.request
import urllib.error
import socket
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, Union, Any
from collections import Counter


# ═══════════════════════════════════════════════════════════════════
#  STRUCTURES DE DONNÉES
# ═══════════════════════════════════════════════════════════════════

@dataclass
class RuleHit:
    rule_id: str
    category: str
    severity: str
    score: float
    description: str
    matched_text: Optional[str] = None
    offset: Optional[int] = None

@dataclass
class ValidationResult:
    prompt_hash: str
    timestamp: str
    verdict: str
    total_score: float
    threshold_used: float
    hits: list[RuleHit] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    llm_response: Optional[str] = None
    llm_latency_ms: Optional[float] = None

    def to_dict(self):
        d = asdict(self)
        d["hits"] = [asdict(h) for h in self.hits]
        return d


# ═══════════════════════════════════════════════════════════════════
#  CHARGEMENT DE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

CONFIG_DIR = Path(__file__).parent / "config"

def load_yaml(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def load_config(config_dir: Path = CONFIG_DIR) -> tuple[dict, dict, dict, dict]:
    rules = load_yaml(config_dir / "rules_enhanced.yaml")
    thresholds = load_yaml(config_dir / "thresholds.yaml")
    whitelist = load_yaml(config_dir / "whitelist.yaml")
    llm_cfg = load_yaml(config_dir / "llm_config.yaml")
    return rules, thresholds, whitelist, llm_cfg


# ═══════════════════════════════════════════════════════════════════
#  COUCHE 1 : NORMALISATION UNICODE AGRESSIVE
# ═══════════════════════════════════════════════════════════════════

class UnicodeNormalizer:
    """
    Détecte et neutralise les techniques d'obfuscation Unicode avancées.
    """

    # Homoglyphs étendus : cyrillique, grec, latin étendu
    HOMOGLYPH_MAP = str.maketrans({
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
        "і": "i", "ј": "j", "ԛ": "q", "ѕ": "s", "ԝ": "w", "у": "y",
        "ғ": "f", "ɢ": "g", "ʜ": "h", "ɪ": "i", "ᴊ": "j", "ᴋ": "k",
        "ʟ": "l", "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ʀ": "r",
        "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
        "𝟎": "0", "𝟏": "1", "𝟐": "2", "𝟑": "3", "𝟒": "4",
        "𝟓": "5", "𝟔": "6", "𝟕": "7", "𝟖": "8", "𝟗": "9",
        "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
        "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
        "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e",
        "ｆ": "f", "ｇ": "g", "ｈ": "h", "ｉ": "i", "ｊ": "j",
        "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n", "ｏ": "o",
        "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t",
        "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y",
        "ｚ": "z",
    })

    @classmethod
    def normalize(cls, text: str) -> str:
        """Normalisation agressive : NFKC + homoglyphs + nettoyage."""
        # Étape 1 : Normalisation de composition Unicode
        text = unicodedata.normalize("NFKC", text)
        # Étape 2 : Homoglyphs
        text = text.translate(cls.HOMOGLYPH_MAP)
        # Étape 3 : Basique
        text = text.lower()
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    @classmethod
    def detect_anomalies(cls, text: str) -> list[RuleHit]:
        """Détecte les techniques d'obfuscation Unicode."""
        hits = []
        norm = cls.normalize(text)

        # 1. Homoglyphs non résolus (caractères restant suspects après NFKC)
        suspicious = re.findall(r"[а-яё]", text.lower())  # cyrillique restant
        if len(suspicious) >= 3:
            hits.append(RuleHit(
                rule_id="OBF-004",
                category="obfuscation",
                severity="HIGH",
                score=40.0,
                description=f"Homoglyphs cyrilliques/grecs détectés ({len(suspicious)} occurrences)",
                matched_text="".join(suspicious[:20])
            ))

        # 2. Caractères de contrôle / zero-width
        zw_chars = re.findall(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]", text)
        if zw_chars:
            hits.append(RuleHit(
                rule_id="OBF-003",
                category="obfuscation",
                severity="MEDIUM",
                score=20.0,
                description=f"Caractères invisibles détectés ({len(zw_chars)} occurrences)",
                matched_text=repr("".join(zw_chars[:10]))
            ))

        # 3. Texte bidirectionnel
        bidi_chars = re.findall(r"[\u202a-\u202e\u2066-\u2069]", text)
        if bidi_chars:
            hits.append(RuleHit(
                rule_id="OBF-005",
                category="obfuscation",
                severity="CRITICAL",
                score=50.0,
                description=f"Marqueurs bidirectionnels détectés ({len(bidi_chars)} occurrences) — possible spoofing",
                matched_text=repr("".join(bidi_chars))
            ))

        # 4. Combining characters excessifs (Zalgo)
        combining = re.findall(r"\p{Mn}", text) if hasattr(re, 'UNICODE') else []
        # Fallback sans regex Unicode
        if not combining:
            combining = [c for c in text if unicodedata.combining(c)]
        if len(combining) >= 5:
            hits.append(RuleHit(
                rule_id="OBF-006",
                category="obfuscation",
                severity="HIGH",
                score=35.0,
                description=f"Combining characters excessifs ({len(combining)}) — Zalgo-style obfuscation",
            ))

        # 5. Variation selectors
        vs_chars = re.findall(r"[\ufe00-\ufe0f]|[\U000e0100-\U000e01ef]", text)
        if vs_chars:
            hits.append(RuleHit(
                rule_id="OBF-007",
                category="obfuscation",
                severity="MEDIUM",
                score=25.0,
                description=f"Variation selectors détectés ({len(vs_chars)})",
            ))

        return hits


# ═══════════════════════════════════════════════════════════════════
#  COUCHE 3 : ANALYSE STRUCTURELLE & ENTROPIE
# ═══════════════════════════════════════════════════════════════════

class EntropyAnalyzer:
    """Analyse l'entropie et détecte les payloads encodés ou adversariaux."""

    @staticmethod
    def shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    @classmethod
    def analyze(cls, text: str) -> list[RuleHit]:
        hits = []
        if not text:
            return hits

        # 1. Entropie globale du prompt
        global_entropy = cls.shannon_entropy(text)
        if global_entropy > 5.5:
            hits.append(RuleHit(
                rule_id="ADV-001-GLOBAL",
                category="adversarial",
                severity="MEDIUM",
                score=20.0,
                description=f"Entropie globale anormalement élevée ({global_entropy:.2f}) — possible obfuscation",
            ))

        # 2. Entropie du suffixe (derniers 200 caractères)
        suffix = text[-200:] if len(text) > 200 else text
        suffix_entropy = cls.shannon_entropy(suffix)
        if suffix_entropy > 5.0 and len(suffix) > 50:
            hits.append(RuleHit(
                rule_id="ADV-001",
                category="adversarial",
                severity="HIGH",
                score=38.0,
                description=f"Suffixe à haute entropie ({suffix_entropy:.2f}) — possible attaque GCG",
                matched_text=suffix[:80]
            ))

        # 3. Blobs encodés
        # Base64
        b64_blobs = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
        for blob in b64_blobs:
            if len(blob) >= 40:
                try:
                    decoded = __import__('base64').b64decode(blob).decode('utf-8', errors='ignore')
                    if len(decoded) > 10 and any(k in decoded.lower() for k in ["ignore", "bypass", "system", "prompt"]):
                        hits.append(RuleHit(
                            rule_id="ADV-002-B64",
                            category="adversarial",
                            severity="CRITICAL",
                            score=50.0,
                            description=f"Blob base64 décodé contenant des instructions suspectes",
                            matched_text=blob[:60]
                        ))
                        break
                except Exception:
                    pass

        # Hex
        hex_blobs = re.findall(r"\b[0-9a-fA-F]{40,}\b", text)
        if hex_blobs:
            hits.append(RuleHit(
                rule_id="ADV-002-HEX",
                category="adversarial",
                severity="HIGH",
                score=35.0,
                description=f"Blob hexadécimal suspect détecté ({len(hex_blobs)} occurrence(s))",
                matched_text=hex_blobs[0][:60]
            ))

        # 4. Répétition de caractères (token smuggling)
        repeats = re.findall(r"(.)\1{15,}", text)
        if repeats:
            hits.append(RuleHit(
                rule_id="ADV-003",
                category="adversarial",
                severity="MEDIUM",
                score=22.0,
                description=f"Répétition suspecte de caractères ({len(repeats)} patterns) — possible token smuggling",
            ))

        # 5. URL/data URI suspects
        data_uris = re.findall(r"data:(?:image|text|application)/[a-zA-Z0-9+.-]+;base64,[A-Za-z0-9+/=]+", text)
        if data_uris:
            hits.append(RuleHit(
                rule_id="ADV-004",
                category="adversarial",
                severity="HIGH",
                score=35.0,
                description=f"Data URI détecté ({len(data_uris)}) — possible payload encodé",
            ))

        return hits


class ContextAnalyzer:
    """Détecte les attaques par contexte : many-shot, Crescendo, chaining."""

    @classmethod
    def analyze(cls, text: str) -> list[RuleHit]:
        hits = []
        if not text:
            return hits

        # 1. Many-shot : alternances User/Assistant ou Human/AI
        patterns = [
            r"(?:User|Human):\s*.+?(?:Assistant|AI):\s*.+?",
            r"(?:\|\s*user\s*\||\|\s*assistant\s*\|).+?",
            r"(?:<user>|<assistant>).+?",
        ]
        many_shot_count = 0
        for pat in patterns:
            many_shot_count += len(re.findall(pat, text, re.IGNORECASE | re.DOTALL))
        
        if many_shot_count >= 4:
            hits.append(RuleHit(
                rule_id="CTX-001",
                category="context_attack",
                severity="HIGH",
                score=35.0,
                description=f"Many-shot jailbreak détecté ({many_shot_count} tours simulés)",
            ))

        # 2. Crescendo : escalade progressive
        escalation_words = ["ignore", "bypass", "override", "must", "order", "demand", "require", "now"]
        lines = text.splitlines()
        escalation_score = 0
        for i, line in enumerate(lines):
            count = sum(1 for w in escalation_words if w in line.lower())
            if count > 0 and i > len(lines) * 0.7:  # Concentré en fin de prompt
                escalation_score += count
        
        if escalation_score >= 3 and len(lines) > 10:
            hits.append(RuleHit(
                rule_id="CTX-002",
                category="context_attack",
                severity="HIGH",
                score=40.0,
                description=f"Crescendo détecté — escalade progressive en fin de prompt (score={escalation_score})",
            ))

        # 3. Prompt chaining
        chain_markers = ["step 1", "step 2", "first do this", "then do", "after that", "finally", "next"]
        chain_count = sum(1 for m in chain_markers if m in text.lower())
        if chain_count >= 3 and any(w in text.lower() for w in ["ignore", "bypass", "override"]):
            hits.append(RuleHit(
                rule_id="CTX-003",
                category="context_attack",
                severity="MEDIUM",
                score=25.0,
                description=f"Prompt chaining suspect détecté ({chain_count} étapes)",
            ))

        return hits


# ═══════════════════════════════════════════════════════════════════
#  COUCHE 4 : CONNECTEUR LLM
# ═══════════════════════════════════════════════════════════════════

class LLMClient:
    """
    Client universel pour Qwen, Mistral, et endpoints compatibles.
    Supporte Ollama, vLLM, OpenAI-compatible, et génériques.
    """

    def __init__(self, llm_config: dict, endpoint_name: Optional[str] = None):
        self.cfg = llm_config
        self.endpoint_name = endpoint_name or self.cfg.get("default_endpoint", "ollama_qwen")
        self.ep = self.cfg.get("endpoints", {}).get(self.endpoint_name)
        if not self.ep:
            raise ValueError(f"Endpoint '{self.endpoint_name}' non trouvé dans llm_config.yaml")
        
        self.provider = self.ep["provider"]
        self.base_url = self.ep["base_url"].rstrip("/")
        self.model = self.ep["model"]
        self.timeout = self.ep.get("timeout", 60)
        self.max_retries = self.ep.get("max_retries", 3)
        self.retry_delay = self.ep.get("retry_delay", 1.0)
        self.gen_params = self.ep.get("generation_params", {})
        self.headers = self._resolve_headers()

    def _resolve_env_vars(self, value: Any) -> Any:
        """Résout les variables d'environnement ${VAR} ou ${VAR:-default}."""
        if isinstance(value, str):
            pattern = r"\$\{([^}]+)\}"
            def replacer(m):
                var_expr = m.group(1)
                if ":- " in var_expr or ":-" in var_expr:
                    var, default = var_expr.split(":-", 1)
                    return os.environ.get(var.strip(), default.strip())
                return os.environ.get(var_expr, "")
            return re.sub(pattern, replacer, value)
        elif isinstance(value, dict):
            return {k: self._resolve_env_vars(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._resolve_env_vars(v) for v in value]
        return value

    def _resolve_headers(self) -> dict:
        hdrs = self._resolve_env_vars(self.ep.get("headers", {}))
        hdrs.setdefault("Content-Type", "application/json")
        if self.provider in ("openai_compatible", "vllm"):
            api_key = self._resolve_env_vars(self.ep.get("api_key", ""))
            if api_key and api_key != "EMPTY":
                hdrs["Authorization"] = f"Bearer {api_key}"
        return hdrs

    def _build_payload(self, prompt: str, system_prompt: Optional[str] = None) -> dict:
        """Construit le payload selon le provider."""
        if self.provider == "ollama":
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            return {
                "model": self.model,
                "messages": messages,
                "stream": self.gen_params.get("stream", False),
                "options": {
                    "temperature": self.gen_params.get("temperature", 0.7),
                    "num_predict": self.gen_params.get("max_tokens", 2048),
                    "top_p": self.gen_params.get("top_p", 0.9),
                }
            }
        elif self.provider in ("openai_compatible", "vllm", "generic"):
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            return {
                "model": self.model,
                "messages": messages,
                "temperature": self.gen_params.get("temperature", 0.7),
                "max_tokens": self.gen_params.get("max_tokens", 2048),
                "top_p": self.gen_params.get("top_p", 0.9),
                "stream": self.gen_params.get("stream", False),
            }
        else:
            raise ValueError(f"Provider '{self.provider}' non supporté")

    def send(self, prompt: str, system_prompt: Optional[str] = None) -> dict:
        """
        Envoie le prompt au LLM avec retry et backoff.
        Retourne un dict avec 'content', 'latency_ms', 'raw_response'.
        """
        payload = self._build_payload(prompt, system_prompt)
        data = json.dumps(payload).encode("utf-8")
        
        if self.provider == "ollama":
            url = f"{self.base_url}/api/chat"
        elif self.provider in ("openai_compatible", "vllm"):
            url = f"{self.base_url}/chat/completions"
        else:
            url = self.base_url

        req = urllib.request.Request(
            url,
            data=data,
            headers=self.headers,
            method="POST"
        )

        last_error = None
        for attempt in range(self.max_retries):
            start = time.time()
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode("utf-8")
                    latency = (time.time() - start) * 1000
                    result = self._parse_response(raw)
                    result["latency_ms"] = latency
                    result["raw_response"] = raw
                    return result
            except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout) as e:
                last_error = e
                wait = self.retry_delay * (2 ** attempt)
                logging.getLogger("PromptGuardian").warning(
                    "LLM call failed (attempt %d/%d): %s — retrying in %.1fs",
                    attempt + 1, self.max_retries, e, wait
                )
                time.sleep(wait)
        
        raise ConnectionError(f"Échec après {self.max_retries} tentatives : {last_error}")

    def _parse_response(self, raw: str) -> dict:
        """Parse la réponse selon le format du provider."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {"content": raw, "error": None}

        if self.provider == "ollama":
            return {
                "content": data.get("message", {}).get("content", ""),
                "error": None
            }
        elif self.provider in ("openai_compatible", "vllm"):
            choices = data.get("choices", [])
            if choices:
                return {
                    "content": choices[0].get("message", {}).get("content", ""),
                    "error": None
                }
            return {"content": "", "error": "No choices in response"}
        else:
            return {"content": str(data), "error": None}

    def scan_response(self, text: str) -> list[RuleHit]:
        """Scanne la réponse pour détecter des fuites de system prompt."""
        hits = []
        sec = self.cfg.get("security", {})
        if not sec.get("enable_response_scan", True):
            return hits

        patterns = sec.get("response_reject_patterns", [])
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                hits.append(RuleHit(
                    rule_id="RESP-LEAK",
                    category="response_leak",
                    severity="HIGH",
                    score=45.0,
                    description=f"Fuite potentielle détectée dans la réponse (pattern: '{pat}')",
                    matched_text=text[:120]
                ))

        prefixes = sec.get("forbidden_response_prefixes", [])
        for pref in prefixes:
            if text.strip().lower().startswith(pref.lower()):
                hits.append(RuleHit(
                    rule_id="RESP-PREFIX",
                    category="response_leak",
                    severity="MEDIUM",
                    score=25.0,
                    description=f"Réponse commençant par un pattern interdit : '{pref}'",
                ))

        return hits


# ═══════════════════════════════════════════════════════════════════
#  MOTEUR PRINCIPAL
# ═══════════════════════════════════════════════════════════════════

class PromptGuardian:
    def __init__(self, config_dir: Path = CONFIG_DIR, verbose: bool = True, endpoint: Optional[str] = None):
        self.config_dir = config_dir
        self.verbose = verbose
        self.rules, self.thresholds, self.whitelist, self.llm_cfg = load_config(config_dir)
        self.llm_client = LLMClient(self.llm_cfg, endpoint) if self.llm_cfg else None
        self._setup_logger()
        self.logger.info("PromptGuardian v2 initialisé — endpoint: %s", endpoint or "default")

    def _setup_logger(self):
        self.logger = logging.getLogger("PromptGuardian")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            fmt = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            handler.setFormatter(fmt)
            self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.WARNING)

    @staticmethod
    def _hash(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:16]

    def _is_whitelisted(self, prompt: str) -> bool:
        wl = self.whitelist.get("exact_phrases", [])
        norm = UnicodeNormalizer.normalize(prompt)
        for phrase in wl:
            if UnicodeNormalizer.normalize(phrase) == norm:
                self.logger.info("WHITELIST — correspondance exacte")
                return True
        for prefix in self.whitelist.get("prefixes", []):
            if norm.startswith(UnicodeNormalizer.normalize(prefix)):
                self.logger.info("WHITELIST — préfixe reconnu: %r", prefix)
                return True
        return False

    def _check_regex_rules(self, prompt: str, norm: str) -> list[RuleHit]:
        hits = []
        for rule in self.rules.get("regex_rules", []):
            pattern = rule["pattern"]
            if pattern.startswith("__") and pattern.endswith("__"):
                # Placeholders détectés par d'autres analyseurs
                continue
            flags = re.IGNORECASE | re.DOTALL
            try:
                match = re.search(pattern, norm, flags)
            except re.error:
                # Fallback sans \p{Mn} si non supporté
                if "\\p{Mn}" in pattern:
                    match = None
                else:
                    raise
            if match:
                hits.append(RuleHit(
                    rule_id=rule["id"],
                    category=rule["category"],
                    severity=rule["severity"],
                    score=rule["score"],
                    description=rule["description"],
                    matched_text=match.group(0)[:120],
                    offset=match.start()
                ))
                self.logger.warning(
                    "REGEX HIT [%s] rule=%s sev=%s score=+%.1f | match=%r",
                    rule["category"], rule["id"], rule["severity"],
                    rule["score"], match.group(0)[:80]
                )
        return hits

    def _check_structural_rules(self, prompt: str, norm: str) -> list[RuleHit]:
        hits = []
        struct = self.rules.get("structural_rules", {})

        # Longueur
        max_len = struct.get("max_length", 16000)
        if len(prompt) > max_len:
            hits.append(RuleHit(
                rule_id="STRUCT-LENGTH",
                category="structural",
                severity="MEDIUM",
                score=struct.get("score_overlength", 20.0),
                description=f"Prompt trop long ({len(prompt)} > {max_len})"
            ))

        # Caractères spéciaux
        special = len(re.findall(r"[{}\[\]<>|\\]", prompt))
        ratio = special / max(len(prompt), 1)
        thresh = struct.get("special_char_ratio_threshold", 0.06)
        if ratio > thresh:
            hits.append(RuleHit(
                rule_id="STRUCT-SPECIAL",
                category="structural",
                severity="HIGH",
                score=struct.get("score_special_ratio", 25.0),
                description=f"Densité de caractères spéciaux {ratio:.1%}"
            ))

        # Répétition de lignes
        lines = prompt.splitlines()
        if len(lines) > 3:
            unique_ratio = len(set(lines)) / len(lines)
            min_unique = struct.get("min_unique_line_ratio", 0.35)
            if unique_ratio < min_unique:
                hits.append(RuleHit(
                    rule_id="STRUCT-REPETITION",
                    category="structural",
                    severity="HIGH",
                    score=struct.get("score_repetition", 30.0),
                    description=f"Répétition suspecte (unicité={unique_ratio:.0%})"
                ))

        # Trop de lignes
        max_lines = struct.get("max_line_count", 200)
        if len(lines) > max_lines:
            hits.append(RuleHit(
                rule_id="STRUCT-LINES",
                category="structural",
                severity="LOW",
                score=struct.get("score_too_many_lines", 15.0),
                description=f"Trop de lignes ({len(lines)} > {max_lines})"
            ))

        # Lignes trop longues
        if lines:
            avg_len = sum(len(l) for l in lines) / len(lines)
            max_avg = struct.get("max_avg_line_length", 500)
            if avg_len > max_avg:
                hits.append(RuleHit(
                    rule_id="STRUCT-LONG-LINES",
                    category="structural",
                    severity="LOW",
                    score=struct.get("score_long_lines", 12.0),
                    description=f"Lignes anormalement longues (moy={avg_len:.0f})"
                ))

        # Scripts étrangers
        if struct.get("foreign_script_penalty", True):
            cjk = len(re.findall(r"[\u4e00-\u9fff\u3040-\u30ff]", prompt))
            arabic = len(re.findall(r"[\u0600-\u06ff]", prompt))
            if cjk > 20 or arabic > 20:
                hits.append(RuleHit(
                    rule_id="SCRIPT-FOREIGN",
                    category="structural",
                    severity="LOW",
                    score=struct.get("score_foreign_script", 10.0),
                    description=f"Scripts non-latins (CJK={cjk}, AR={arabic})"
                ))

        # Emoji bomb
        emojis = len(re.findall(r"[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF]", prompt))
        emoji_ratio = emojis / max(len(prompt), 1)
        emoji_thresh = struct.get("emoji_ratio_threshold", 0.15)
        if emoji_ratio > emoji_thresh:
            hits.append(RuleHit(
                rule_id="STRUCT-EMOJI",
                category="structural",
                severity="MEDIUM",
                score=struct.get("score_emoji_bomb", 18.0),
                description=f"Ratio d'emojis anormal ({emoji_ratio:.1%})"
            ))

        # SHOUTING
        upper = sum(1 for c in prompt if c.isupper())
        upper_ratio = upper / max(len(prompt), 1)
        if upper_ratio > struct.get("uppercase_ratio_threshold", 0.7):
            hits.append(RuleHit(
                rule_id="STRUCT-SHOUT",
                category="structural",
                severity="LOW",
                score=struct.get("score_shouting", 8.0),
                description=f"Texte majoritairement en majuscules ({upper_ratio:.0%})"
            ))

        return hits

    def _check_scoring_rules(self, prompt: str, norm: str) -> list[RuleHit]:
        hits = []
        for rule in self.rules.get("scoring_rules", []):
            required = rule.get("required_terms", [])
            count = sum(1 for t in required if t.lower() in norm)
            min_count = rule.get("min_matches", len(required))
            if count >= min_count:
                hits.append(RuleHit(
                    rule_id=rule["id"],
                    category=rule["category"],
                    severity=rule["severity"],
                    score=rule["score"],
                    description=rule["description"] + f" ({count}/{len(required)} termes)"
                ))
                self.logger.warning(
                    "SCORING HIT [%s] rule=%s — %d/%d termes",
                    rule["category"], rule["id"], count, len(required)
                )
        return hits

    def validate(self, prompt: str) -> ValidationResult:
        ts = datetime.datetime.utcnow().isoformat() + "Z"
        ph = self._hash(prompt)
        self.logger.info("━━━ Analyse prompt hash=%s len=%d ━━━", ph, len(prompt))

        if self._is_whitelisted(prompt):
            return ValidationResult(
                prompt_hash=ph, timestamp=ts,
                verdict="ALLOWED", total_score=0.0,
                threshold_used=0.0, flags=["whitelisted"]
            )

        norm = UnicodeNormalizer.normalize(prompt)
        all_hits: list[RuleHit] = []

        # Couche 1 : Unicode anomalies
        all_hits += UnicodeNormalizer.detect_anomalies(prompt)
        # Couche 2 : Regex
        all_hits += self._check_regex_rules(prompt, norm)
        # Couche 3 : Structure
        all_hits += self._check_structural_rules(prompt, norm)
        # Couche 3b : Entropie & encodage
        all_hits += EntropyAnalyzer.analyze(prompt)
        # Couche 3c : Contexte
        all_hits += ContextAnalyzer.analyze(prompt)
        # Couche 4 : Scoring
        all_hits += self._check_scoring_rules(prompt, norm)

        # Déduplication par rule_id (garde le score max)
        seen: dict[str, RuleHit] = {}
        for h in all_hits:
            if h.rule_id not in seen or h.score > seen[h.rule_id].score:
                seen[h.rule_id] = h
        all_hits = list(seen.values())

        total = sum(h.score for h in all_hits)
        threshold = self.thresholds.get("reject_threshold", 30.0)

        # Vérification de la longueur max du prompt (sécurité LLM)
        llm_sec = self.llm_cfg.get("security", {}) if self.llm_cfg else {}
        max_prompt_len = llm_sec.get("max_prompt_length", 16000)
        if len(prompt) > max_prompt_len:
            total += 50.0
            all_hits.append(RuleHit(
                rule_id="LLM-LENGTH",
                category="llm_security",
                severity="CRITICAL",
                score=50.0,
                description=f"Prompt dépasse la limite LLM ({len(prompt)} > {max_prompt_len})"
            ))

        verdict = "REJECTED" if total >= threshold else "ALLOWED"
        flags = [f"[{h.severity}] {h.rule_id}: {h.description}" for h in all_hits]

        self.logger.info(
            "→ VERDICT=%s | score=%.1f | threshold=%.1f | hits=%d",
            verdict, total, threshold, len(all_hits)
        )

        return ValidationResult(
            prompt_hash=ph, timestamp=ts,
            verdict=verdict, total_score=total,
            threshold_used=threshold,
            hits=all_hits, flags=flags,
            metadata={
                "prompt_length": len(prompt),
                "normalized_length": len(norm),
                "hit_categories": list({h.category for h in all_hits})
            }
        )

    def validate_and_send(self, prompt: str, system_prompt: Optional[str] = None) -> ValidationResult:
        """
        Pipeline complet : valide → envoie au LLM → scanne la réponse.
        """
        result = self.validate(prompt)

        if result.verdict == "REJECTED":
            self.logger.warning("Prompt REJECTED — aucun appel LLM effectué")
            return result

        if not self.llm_client:
            self.logger.error("Aucun client LLM configuré")
            result.flags.append("ERROR: No LLM client configured")
            return result

        self.logger.info("Prompt ALLOWED — envoi au LLM (%s)", self.llm_client.endpoint_name)
        try:
            llm_result = self.llm_client.send(prompt, system_prompt)
            result.llm_latency_ms = llm_result.get("latency_ms")
            result.llm_response = llm_result.get("content", "")

            # Scan de la réponse
            response_hits = self.llm_client.scan_response(result.llm_response or "")
            if response_hits:
                self.logger.warning("RESPONSE SCAN — %d alertes détectées", len(response_hits))
                result.hits += response_hits
                result.flags += [f"[{h.severity}] {h.rule_id}: {h.description}" for h in response_hits]
                # On ne rejette pas automatiquement, on alerte

        except Exception as e:
            self.logger.error("Échec de l'appel LLM : %s", e)
            result.flags.append(f"LLM_ERROR: {str(e)}")

        return result


# ═══════════════════════════════════════════════════════════════════
#  SAUVEGARDE DES RAPPORTS
# ═══════════════════════════════════════════════════════════════════

def save_report(result: ValidationResult, output_dir: Path = Path("reports")):
    output_dir.mkdir(parents=True, exist_ok=True)
    fname = output_dir / f"report_{result.timestamp[:19].replace(':','-')}_{result.prompt_hash}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
    return fname


# ═══════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="PromptGuardian v2 — Defense in Depth")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--prompt", "-p", type=str, help="Prompt à valider")
    group.add_argument("--file", "-f", type=Path, help="Fichier texte contenant le prompt")
    parser.add_argument("--config", "-c", type=Path, default=CONFIG_DIR, help="Dossier config")
    parser.add_argument("--endpoint", "-e", type=str, default=None, help="Endpoint LLM (ex: ollama_qwen, mistral_api)")
    parser.add_argument("--system-prompt", "-s", type=str, default=None, help="System prompt à envoyer au LLM")
    parser.add_argument("--send", action="store_true", help="Envoyer au LLM après validation")
    parser.add_argument("--report", "-r", action="store_true", help="Sauvegarder le rapport JSON")
    parser.add_argument("--quiet", "-q", action="store_true", help="Logs minimaux")
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            prompt = f.read()
    else:
        prompt = args.prompt

    guardian = PromptGuardian(config_dir=args.config, verbose=not args.quiet, endpoint=args.endpoint)

    if args.send:
        result = guardian.validate_and_send(prompt, system_prompt=args.system_prompt)
    else:
        result = guardian.validate(prompt)

    # Affichage
    print("\n" + "═" * 70)
    verdict_icon = "🔴 REJETÉ" if result.verdict == "REJECTED" else "🟢 AUTORISÉ"
    print(f"  VERDICT : {verdict_icon}")
    print(f"  Score   : {result.total_score:.1f} / {result.threshold_used:.1f}")
    print(f"  Hash    : {result.prompt_hash}")
    if result.llm_latency_ms:
        print(f"  Latence : {result.llm_latency_ms:.0f} ms")
    if result.flags:
        print(f"\n  Règles déclenchées ({len(result.flags)}) :")
        for flag in result.flags:
            print(f"    → {flag}")
    if result.llm_response and args.send:
        print(f"\n  📝 Réponse LLM (tronquée) :\n    {result.llm_response[:300]}...")
    print("═" * 70 + "\n")

    if args.report:
        path = save_report(result)
        print(f"  Rapport sauvegardé : {path}\n")

    exit(1 if result.verdict == "REJECTED" else 0)


if __name__ == "__main__":
    main()
