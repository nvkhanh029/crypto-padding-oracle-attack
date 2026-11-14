"""Vaudenay's padding-oracle attack for one CBC block."""
from __future__ import annotations

from collections.abc import MutableSequence
from padding_oracle.core.contracts import BLOCK_SIZE, BaseOracle


def attack(oracle: BaseOracle, ciphertext: bytes, n_bytes: int, **params) -> bytes:
    """Recover the last n_bytes of one plaintext block using a perfect oracle.

    Optional byte_query_counts receives measured oracle-query deltas, from
    right to left. Query accounting remains owned by oracle.queries.
    Raises RuntimeError if no guess gives valid padding for a byte 
    (for example, against Encrypt-then-MAC or AES-GCM, where the oracle always says invalid).
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")
    if len(ciphertext) != 2 * BLOCK_SIZE:
        raise ValueError("attack requires exactly two 16-byte blocks")
    if not isinstance(n_bytes, int) or isinstance(n_bytes, bool):
        raise TypeError("n_bytes must be an integer")
    if not 1 <= n_bytes <= BLOCK_SIZE:
        raise ValueError("n_bytes must be between 1 and 16")

    byte_query_counts = params.pop("byte_query_counts", None)
    if params:
        raise TypeError("unexpected attack parameter(s): " + ", ".join(sorted(params)))
    if byte_query_counts is not None and not isinstance(byte_query_counts, MutableSequence):
        raise TypeError("byte_query_counts must be a mutable sequence")

    original_previous = bytes(ciphertext[:BLOCK_SIZE])
    target_block = bytes(ciphertext[BLOCK_SIZE:])
    intermediate = bytearray(BLOCK_SIZE)
    recovered = bytearray(BLOCK_SIZE)

    for padding_value in range(1, n_bytes + 1):
        index = BLOCK_SIZE - padding_value
        before = oracle.queries
        crafted_previous = bytearray(original_previous)

        for known_index in range(index + 1, BLOCK_SIZE):
            crafted_previous[known_index] = (
                intermediate[known_index] ^ padding_value
            )

        found = False
        for guess in range(256):
            crafted_previous[index] = guess
            probe = bytes(crafted_previous) + target_block
            if not oracle.query(probe):
                continue

            # Discard accidental valid padding longer than one byte.
            if padding_value == 1:
                confirmation = bytearray(crafted_previous)
                confirmation[index - 1] ^= 1
                if not oracle.query(bytes(confirmation) + target_block):
                    continue

            intermediate[index] = guess ^ padding_value
            recovered[index] = intermediate[index] ^ original_previous[index]
            found = True
            break

        if not found:
            raise RuntimeError(f"could not recover plaintext byte at offset {index}")
        if byte_query_counts is not None:
            byte_query_counts.append(oracle.queries - before)

    return bytes(recovered[BLOCK_SIZE - n_bytes:])
