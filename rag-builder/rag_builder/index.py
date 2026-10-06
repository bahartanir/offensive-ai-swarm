"""FAISS vector index with IndexIDMap for stable chunk ID mapping."""

from pathlib import Path

import numpy as np

DIMENSION = 384


def _normalize(vectors: np.ndarray) -> np.ndarray:
    """L2-normalize vectors for cosine similarity via inner product."""
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms = np.where(norms == 0, 1, norms)
    return (vectors / norms).astype(np.float32)


class VectorIndex:
    """FAISS IndexIDMap wrapping IndexFlatIP for cosine similarity search."""

    def __init__(self, path: Path, dimension: int = DIMENSION):
        import faiss

        self._faiss = faiss
        self.path = Path(path)
        self.dimension = dimension
        if self.path.exists():
            self.index = faiss.read_index(str(self.path))
        else:
            base = faiss.IndexFlatIP(dimension)
            self.index = faiss.IndexIDMap2(base)

    def add(self, vectors: np.ndarray, ids: np.ndarray):
        """Add L2-normalized vectors with corresponding chunk IDs."""
        normalized = _normalize(vectors)
        self.index.add_with_ids(normalized, ids.astype(np.int64))

    def search(self, query_vectors: np.ndarray, k: int = 5) -> tuple[np.ndarray, np.ndarray]:
        """Search for k nearest neighbors. Returns (scores, ids)."""
        if self.index.ntotal == 0:
            empty = np.array([[-1] * k], dtype=np.int64)
            zeros = np.zeros((1, k), dtype=np.float32)
            return zeros, empty
        normalized = _normalize(query_vectors)
        actual_k = min(k, self.index.ntotal)
        return self.index.search(normalized, actual_k)

    def remove(self, ids: np.ndarray):
        """Remove vectors by their IDs."""
        self.index.remove_ids(ids.astype(np.int64))

    def size(self) -> int:
        return self.index.ntotal

    def save(self):
        """Persist index to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._faiss.write_index(self.index, str(self.path))

    def save_to(self, path: Path):
        """Save to a specific path (for atomic rebuild)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        self._faiss.write_index(self.index, str(path))
