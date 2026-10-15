import numpy as np
import torch
from sentence_transformers import SentenceTransformer
from typing import List, Tuple

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

class LatentOODFilter:
    """
    Evaluates semantic representation density using Mahalanobis distance
    over penultimate sentence embeddings.
    """

    def __init__(self, model_name: str = MODEL_NAME, ridge_epsilon: float = 1e-3):
        self.encoder = SentenceTransformer(model_name, device="cpu")
        self.ridge_epsilon = ridge_epsilon
        self.centroid: np.ndarray = None
        self.inv_cov: np.ndarray = None
        self.is_fitted: bool = False

    def fit_in_distribution(self, id_corpus: List[str]):
        """
        Fits empirical class centroid and regularized precision matrix (inverse covariance)
        from representative in-distribution enterprise queries.
        """
        if len(id_corpus) < 2:
            raise ValueError("Corpus must contain at least 2 samples to estimate covariance.")

        embeddings = self.encoder.encode(id_corpus, convert_to_numpy=True, normalize_embeddings=True)
        self.centroid = np.mean(embeddings, axis=0)

        # Compute empirical covariance
        diff = embeddings - self.centroid
        cov = np.cov(diff, rowvar=False)

        # Ridge regularization scaled for low-sample high-dimensional manifolds
        dim = cov.shape[0]
        reg_cov = cov + self.ridge_epsilon * np.eye(dim)

        # Invert regularized covariance matrix
        self.inv_cov = np.linalg.pinv(reg_cov)
        self.is_fitted = True

    def compute_distance(self, query: str) -> float:
        """Computes Mahalanobis distance: sqrt((z - mu)^T Sigma^-1 (z - mu))."""
        if not self.is_fitted:
            raise RuntimeError("LatentOODFilter must be fitted on baseline corpus before scoring.")

        query_emb = self.encoder.encode([query], convert_to_numpy=True, normalize_embeddings=True)[0]
        diff = query_emb - self.centroid
        dist_sq = float(diff @ self.inv_cov @ diff.T)
        return float(np.sqrt(max(0.0, dist_sq)))

    def evaluate_query(self, query: str, threshold: float = 30.0) -> Tuple[bool, float]:
        """
        Scores query against the latent distribution.
        Returns (is_rejected, distance_score).
        """
        distance = self.compute_distance(query)
        is_rejected = bool(distance > threshold)
        return is_rejected, distance