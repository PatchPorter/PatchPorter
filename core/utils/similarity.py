"""
Code similarity calculation utilities.

Provides functions for calculating various similarity metrics
between code snippets, including BLEU and CodeBLEU scores.
"""

import logging
from typing import List, Tuple, Optional

logger = logging.getLogger(__name__)


def calculate_bleu(
    reference: str,
    candidate: str,
    weights: Tuple[float, ...] = (0.25, 0.25, 0.25, 0.25),
) -> float:
    """
    Calculate BLEU score between reference and candidate texts.

    BLEU (Bilingual Evaluation Understudy) measures how similar
    the candidate text is to the reference text.

    Args:
        reference: Reference text
        candidate: Candidate text to compare
        weights: Weights for n-gram precision (default: 4-gram)

    Returns:
        BLEU score between 0 and 1
    """
    try:
        import nltk
        from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
    except ImportError:
        logger.error("NLTK not installed. Install with: pip install nltk")
        return 0.0

    # Tokenize texts
    ref_tokens = nltk.word_tokenize(reference.lower())
    cand_tokens = nltk.word_tokenize(candidate.lower())

    # Handle empty inputs
    if not ref_tokens or not cand_tokens:
        return 0.0

    # Use smoothing to handle cases with no n-gram matches
    smoothie = SmoothingFunction().method4

    try:
        score = sentence_bleu(
            [ref_tokens],
            cand_tokens,
            weights=weights,
            smoothing_function=smoothie,
        )
        return score
    except Exception as e:
        logger.warning(f"BLEU calculation failed: {e}")
        return 0.0


def calculate_codebleu(
    reference: str,
    candidate: str,
    language: str = "javascript",
    weights: Tuple[float, ...] = (0.25, 0.25, 0.25, 0.25),
) -> float:
    """
    Calculate CodeBLEU score for code similarity.

    CodeBLEU is a variant of BLEU specifically designed for code,
    taking into account syntax and semantics.

    Args:
        reference: Reference code
        candidate: Candidate code to compare
        language: Programming language (e.g., 'javascript', 'python')
        weights: Weights for different components

    Returns:
        CodeBLEU score between 0 and 1
    """
    try:
        from codebleu import calc_codebleu
    except ImportError:
        logger.error("codebleu not installed. Install with: pip install codebleu")
        return calculate_bleu(reference, candidate)  # Fallback to BLEU

    try:
        result = calc_codebleu(
            references=[reference],
            predictions=[candidate],
            lang=language,
            weights=weights,
        )
        return result.get("codebleu", 0.0)
    except Exception as e:
        logger.warning(f"CodeBLEU calculation failed: {e}, falling back to BLEU")
        return calculate_bleu(reference, candidate)


def calculate_levenshtein_similarity(
    text1: str,
    text2: str,
) -> float:
    """
    Calculate normalized Levenshtein similarity between two texts.

    Args:
        text1: First text
        text2: Second text

    Returns:
        Similarity score between 0 and 1
    """
    try:
        import Levenshtein
    except ImportError:
        logger.error("Levenshtein not installed. Install with: pip install python-Levenshtein")
        return 0.0

    if not text1 and not text2:
        return 1.0
    if not text1 or not text2:
        return 0.0

    distance = Levenshtein.distance(text1, text2)
    max_len = max(len(text1), len(text2))
    return 1 - (distance / max_len)


def calculate_sequence_similarity(
    text1: str,
    text2: str,
) -> float:
    """
    Calculate sequence similarity using difflib's SequenceMatcher.

    Args:
        text1: First text
        text2: Second text

    Returns:
        Similarity ratio between 0 and 1
    """
    from difflib import SequenceMatcher

    if not text1 and not text2:
        return 1.0
    if not text1 or not text2:
        return 0.0

    return SequenceMatcher(None, text1, text2).ratio()


def find_most_similar(
    target: str,
    candidates: List[str],
    method: str = "bleu",
) -> Tuple[int, float]:
    """
    Find the most similar text from a list of candidates.

    Args:
        target: Target text to match
        candidates: List of candidate texts
        method: Similarity method ('bleu', 'codebleu', 'levenshtein', 'sequence')

    Returns:
        Tuple of (index of most similar, similarity score)
    """
    if not candidates:
        return -1, 0.0

    similarity_funcs = {
        "bleu": calculate_bleu,
        "codebleu": lambda r, c: calculate_codebleu(r, c),
        "levenshtein": calculate_levenshtein_similarity,
        "sequence": calculate_sequence_similarity,
    }

    func = similarity_funcs.get(method, calculate_bleu)

    similarities = [func(target, candidate) for candidate in candidates]
    max_score = max(similarities)
    max_index = similarities.index(max_score)

    return max_index, max_score


def rank_by_similarity(
    target: str,
    candidates: List[str],
    method: str = "bleu",
    top_k: Optional[int] = None,
) -> List[Tuple[int, str, float]]:
    """
    Rank candidates by similarity to target.

    Args:
        target: Target text to match
        candidates: List of candidate texts
        method: Similarity method
        top_k: Return only top k results (optional)

    Returns:
        List of (original_index, candidate, score) tuples, sorted by score
    """
    similarity_funcs = {
        "bleu": calculate_bleu,
        "codebleu": lambda r, c: calculate_codebleu(r, c),
        "levenshtein": calculate_levenshtein_similarity,
        "sequence": calculate_sequence_similarity,
    }

    func = similarity_funcs.get(method, calculate_bleu)

    scored = [
        (i, candidate, func(target, candidate))
        for i, candidate in enumerate(candidates)
    ]

    # Sort by score descending
    scored.sort(key=lambda x: x[2], reverse=True)

    if top_k:
        return scored[:top_k]

    return scored


# Alias for compatibility
calculate_levenshtein_ratio = calculate_levenshtein_similarity
