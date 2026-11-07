"""Vaudenay's byte-by-byte CBC padding-oracle attack."""

from __future__ import annotations

from ..core.contracts import BLOCK_SIZE, AttackFailure, BaseOracle, validate_ciphertext


def attack(oracle: BaseOracle, ciphertext: bytes, n_bytes: int = BLOCK_SIZE,
           **params: object) -> bytes:
    """Recover the last ``n_bytes`` of a two-block ciphertext.

    ``params`` is accepted to match the shared attack protocol. This attack
    does not use any tunable parameters.
    """
    del params
    validate_ciphertext(ciphertext)
    if len(ciphertext) != 2 * BLOCK_SIZE:
        raise ValueError("Vaudenay attack requires exactly two ciphertext blocks (IV + target)")
    if not 1 <= n_bytes <= BLOCK_SIZE:
        raise ValueError("n_bytes must be between 1 and 16")

    original_previous = ciphertext[:BLOCK_SIZE]
    target_block = ciphertext[BLOCK_SIZE:]
    intermediate = bytearray(BLOCK_SIZE)
    recovered = bytearray(n_bytes)

    for offset in range(1, n_bytes + 1):
        position = BLOCK_SIZE - offset
        padding = offset
        crafted_previous = bytearray(original_previous)
        for suffix_position in range(position + 1, BLOCK_SIZE):
            crafted_previous[suffix_position] = intermediate[suffix_position] ^ padding

        match: int | None = None
        for plaintext_byte in range(256):
            crafted_previous[position] = (
                original_previous[position] ^ plaintext_byte ^ padding
            )
            if oracle.query(bytes(crafted_previous) + target_block):
                if offset == 1:
                    confirmation = bytearray(crafted_previous)
                    confirmation[position - 1] ^= 1
                    if not oracle.query(bytes(confirmation) + target_block):
                        continue
                match = plaintext_byte
                break

        if match is None:
            raise AttackFailure(
                f"no padding candidate found for byte offset {offset}; "
                "the oracle may not expose padding validity"
            )
        recovered[n_bytes - offset] = match
        intermediate[position] = match ^ original_previous[position]

    return bytes(recovered)
