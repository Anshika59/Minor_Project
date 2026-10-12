"""
Machine Learning Classification Engine (Objective 5)

Extracts combined multi-modal feature vectors (header signals, URL signals,
NLP content metrics, attachment risks, and TF-IDF text representation)
to train and predict the probability that an email is phishing.

Supports benchmarking Logistic Regression and Random Forest classifiers,
evaluating precision, recall, accuracy, and F1-score on held-out splits.
"""

import json
import os
from typing import Dict, List, Any, Optional, Tuple
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from scipy.sparse import hstack, csr_matrix

from src.ingestion import ParsedEmail, EmailParser
from src.header_analyzer import HeaderAnalyzer
from src.url_analyzer import URLAnalyzer
from src.content_analyzer import ContentAnalyzer
from src.attachment_analyzer import AttachmentAnalyzer


FEATURE_NAMES = [
    "header_risk_score",
    "display_name_spoofed",
    "reply_to_mismatch",
    "return_path_mismatch",
    "spf_fail",
    "dkim_fail",
    "dmarc_fail",
    "spf_pass",
    "dkim_pass",
    "dmarc_pass",
    "received_hops",
    "url_risk_score",
    "total_urls",
    "masked_count",
    "blacklisted_count",
    "shortener_count",
    "suspicious_tld_count",
    "ip_url_count",
    "content_risk_score",
    "urgency_score",
    "threat_score",
    "credential_request_score",
    "financial_lure_score",
    "generic_greeting",
    "uppercase_ratio",
    "attachment_risk_score",
    "attachment_count",
    "risky_attachment_count",
    "double_extension_count"
]


class MLEngine:
    """Supervised ML classifier for phishing email detection."""

    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.tfidf_vectorizer = None
        self.metrics = {}
        self.is_trained = False
        self.default_model_path = model_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "models", "phishing_detector.joblib"
        )
        self._try_load()

    def _try_load(self):
        if os.path.exists(self.default_model_path):
            try:
                bundle = joblib.load(self.default_model_path)
                self.model = bundle["model"]
                self.tfidf_vectorizer = bundle["tfidf"]
                self.metrics = bundle.get("metrics", {})
                self.is_trained = True
            except Exception as e:
                print(f"Warning: Could not load saved model ({e}). Will need training.")

    @staticmethod
    def extract_numerical_features(
        email_obj: ParsedEmail,
        header_res: Dict[str, Any],
        url_res: Dict[str, Any],
        content_res: Dict[str, Any],
        att_res: Dict[str, Any]
    ) -> List[float]:
        """Convert module outputs into standard numerical feature vector."""
        auth = header_res.get("authentication", {})
        spf = auth.get("spf", "none")
        dkim = auth.get("dkim", "none")
        dmarc = auth.get("dmarc", "none")

        header_flags = {i.get("rule") for i in header_res.get("indicators", [])}

        vec = [
            float(header_res.get("risk_score", 0.0)),
            1.0 if "display_name_spoofing" in header_flags or "embedded_display_address" in header_flags else 0.0,
            1.0 if "reply_to_mismatch" in header_flags else 0.0,
            1.0 if "return_path_mismatch" in header_flags else 0.0,
            1.0 if spf in ("fail", "softfail") else 0.0,
            1.0 if dkim == "fail" else 0.0,
            1.0 if dmarc == "fail" else 0.0,
            1.0 if spf == "pass" else 0.0,
            1.0 if dkim == "pass" else 0.0,
            1.0 if dmarc == "pass" else 0.0,
            float(len(email_obj.received_headers)),
            float(url_res.get("risk_score", 0.0)),
            float(url_res.get("total_urls", 0)),
            float(url_res.get("masked_count", 0)),
            float(url_res.get("blacklisted_count", 0)),
            float(url_res.get("shortener_count", 0)),
            float(url_res.get("suspicious_tld_count", 0)),
            float(url_res.get("ip_url_count", 0)),
            float(content_res.get("risk_score", 0.0)),
            float(content_res.get("urgency_score", 0.0)),
            float(content_res.get("threat_score", 0.0)),
            float(content_res.get("credential_request_score", 0.0)),
            float(content_res.get("financial_lure_score", 0.0)),
            1.0 if content_res.get("generic_greeting_detected") else 0.0,
            float(content_res.get("uppercase_ratio", 0.0)),
            float(att_res.get("risk_score", 0.0)),
            float(att_res.get("attachment_count", 0)),
            float(att_res.get("risky_attachment_count", 0)),
            float(att_res.get("double_extension_count", 0))
        ]
        return vec

    def predict(
        self,
        email_obj: ParsedEmail,
        header_res: Dict[str, Any],
        url_res: Dict[str, Any],
        content_res: Dict[str, Any],
        att_res: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Predict phishing probability using trained classifier."""
        num_features = self.extract_numerical_features(email_obj, header_res, url_res, content_res, att_res)
        num_arr = np.array([num_features], dtype=np.float32)

        combined_text = f"{email_obj.subject} {email_obj.body_text}".strip()

        if not self.is_trained or self.model is None or self.tfidf_vectorizer is None:
            # Fallback heuristic calculation if model file isn't present
            heuristic_prob = self._heuristic_fallback(num_features)
            return {
                "module": "ml_engine",
                "is_model_trained": False,
                "model_name": "Rule-Weighted Heuristic Fallback",
                "phishing_probability": round(heuristic_prob, 4),
                "phishing_percentage": round(heuristic_prob * 100.0, 1),
                "feature_contributions": self._format_feature_contributions(num_features)
            }

        text_vec = self.tfidf_vectorizer.transform([combined_text])
        sparse_num = csr_matrix(num_arr)
        x_combined = hstack([sparse_num, text_vec])

        # Model probability
        proba = self.model.predict_proba(x_combined)[0]
        # Class 1 is phishing
        phish_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])

        return {
            "module": "ml_engine",
            "is_model_trained": True,
            "model_name": type(self.model).__name__,
            "phishing_probability": round(phish_prob, 4),
            "phishing_percentage": round(phish_prob * 100.0, 1),
            "feature_contributions": self._format_feature_contributions(num_features),
            "benchmark_metrics": self.metrics
        }

    def train_and_benchmark(
        self,
        corpus_path: Optional[str] = None,
        save_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Train and evaluate Random Forest vs Logistic Regression on dataset."""
        default_corpus = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "training_corpus.json"
        )
        data_file = corpus_path or default_corpus
        with open(data_file, "r", encoding="utf-8") as f:
            corpus = json.load(f)

        header_analyzer = HeaderAnalyzer()
        url_analyzer = URLAnalyzer()
        content_analyzer = ContentAnalyzer()
        attachment_analyzer = AttachmentAnalyzer()

        x_num: List[List[float]] = []
        texts: List[str] = []
        y: List[int] = []

        for item in corpus:
            raw_text = f"From: {item['from_raw']}\nSubject: {item['subject']}\n"
            if item.get("reply_to"):
                raw_text += f"Reply-To: {item['reply_to']}\n"
            if item.get("return_path"):
                raw_text += f"Return-Path: {item['return_path']}\n"
            if item.get("auth_results"):
                raw_text += f"Authentication-Results: {item['auth_results']}\n"
            if item.get("received_spf"):
                raw_text += f"Received-SPF: {item['received_spf']}\n"
            raw_text += f"\n{item['body']}"

            email_obj = EmailParser.parse(raw_text)
            # Add synthetic attachments if specified
            for att_info in item.get("attachments", []):
                email_obj.attachments.append(
                    from_dict_attachment(att_info)
                )

            h_res = header_analyzer.analyze(email_obj)
            u_res = url_analyzer.analyze(email_obj)
            c_res = content_analyzer.analyze(email_obj.body_text, email_obj.subject)
            a_res = attachment_analyzer.analyze(email_obj)

            num_vec = self.extract_numerical_features(email_obj, h_res, u_res, c_res, a_res)
            x_num.append(num_vec)
            texts.append(f"{email_obj.subject} {email_obj.body_text}")
            y.append(item["label"])

        x_num_arr = np.array(x_num, dtype=np.float32)
        y_arr = np.array(y, dtype=np.int32)

        # Train TF-IDF vectorizer
        tfidf = TfidfVectorizer(max_features=200, ngram_range=(1, 2), stop_words="english")
        x_tfidf = tfidf.fit_transform(texts)

        # Combine sparse representations
        x_full = hstack([csr_matrix(x_num_arr), x_tfidf])

        # Train/Test Split (80/20)
        x_train, x_test, y_train, y_test = train_test_split(
            x_full, y_arr, test_size=0.25, random_state=42, stratify=y_arr
        )

        # Benchmark 1: Logistic Regression
        lr = LogisticRegression(max_iter=1000, random_state=42)
        lr.fit(x_train, y_train)
        lr_pred = lr.predict(x_test)
        lr_metrics = {
            "model": "LogisticRegression",
            "accuracy": round(float(accuracy_score(y_test, lr_pred)), 4),
            "precision": round(float(precision_score(y_test, lr_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, lr_pred, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_test, lr_pred, zero_division=0)), 4)
        }

        # Benchmark 2: Random Forest
        rf = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
        rf.fit(x_train, y_train)
        rf_pred = rf.predict(x_test)
        rf_metrics = {
            "model": "RandomForestClassifier",
            "accuracy": round(float(accuracy_score(y_test, rf_pred)), 4),
            "precision": round(float(precision_score(y_test, rf_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, rf_pred, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_test, rf_pred, zero_division=0)), 4)
        }

        # Select best model (favoring F1-score and Recall for security applications)
        chosen_model = rf if rf_metrics["f1_score"] >= lr_metrics["f1_score"] else lr
        chosen_metrics = rf_metrics if chosen_model == rf else lr_metrics

        # Retrain chosen model on full dataset for best production coverage
        chosen_model.fit(x_full, y_arr)

        self.model = chosen_model
        self.tfidf_vectorizer = tfidf
        self.metrics = {
            "best_model": chosen_metrics["model"],
            "accuracy": chosen_metrics["accuracy"],
            "precision": chosen_metrics["precision"],
            "recall": chosen_metrics["recall"],
            "f1_score": chosen_metrics["f1_score"],
            "benchmark_comparison": {
                "logistic_regression": lr_metrics,
                "random_forest": rf_metrics
            }
        }
        self.is_trained = True

        # Save model bundle
        out_save_path = save_path or self.default_model_path
        os.makedirs(os.path.dirname(out_save_path), exist_ok=True)
        joblib.dump({
            "model": self.model,
            "tfidf": self.tfidf_vectorizer,
            "metrics": self.metrics
        }, out_save_path)

        # Save metrics JSON alongside
        metrics_json_path = os.path.join(os.path.dirname(out_save_path), "model_metrics.json")
        with open(metrics_json_path, "w", encoding="utf-8") as f:
            json.dump(self.metrics, f, indent=2)

        print(f"Model successfully trained and saved to {out_save_path}")
        return self.metrics

    def _heuristic_fallback(self, num_features: List[float]) -> float:
        """Weighted fallback calculation when model binary is not yet trained."""
        # Normalize weighted components
        h_score = num_features[0]  # header risk
        u_score = num_features[11] # url risk
        c_score = num_features[18] # content risk
        a_score = num_features[25] # attachment risk

        composite = (h_score * 0.3) + (u_score * 0.35) + (c_score * 0.25) + (a_score * 0.1)
        return min(1.0, max(0.0, composite / 100.0))

    def _format_feature_contributions(self, num_features: List[float]) -> Dict[str, float]:
        return {
            name: round(float(val), 2)
            for name, val in zip(FEATURE_NAMES, num_features)
            if val != 0.0
        }


def from_dict_attachment(att_dict: Dict[str, Any]):
    from src.ingestion import EmailAttachment
    return EmailAttachment(
        filename=att_dict.get("filename", ""),
        content_type=att_dict.get("content_type", "application/octet-stream"),
        size_bytes=att_dict.get("size_bytes", 0)
    )
