"""Sentence-transformer embedding wrapper with L2 normalization."""

import logging

import numpy as np

log = logging.getLogger(__name__)

DEFAULT_MODEL = "all-MiniLM-L6-v2"


class Embedder:
    """Wraps sentence-transformers for L2-normalized embeddings.

    Lazy imports so `--dry-run` works even without sentence-transformers
    installed.
    """

    def __init__(self, model_name: str = DEFAULT_MODEL):
        from sentence_transformers import SentenceTransformer

        log.info("Loading embedding model: %s", model_name)
        self.model = SentenceTransformer(model_name)
        self.dimension = self.model.get_sentence_embedding_dimension()

    def embed(self, texts: str | list[str]) -> np.ndarray:
        """Embed text(s) into L2-normalized vectors.

        Args:
            texts: single string or list of strings

        Returns:
            np.ndarray of shape (n, dimension), float32, L2-normalized
        """
        if isinstance(texts, str):
            texts = [texts]
        vectors = self.model.encode(
            texts,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return vectors.astype(np.float32)
