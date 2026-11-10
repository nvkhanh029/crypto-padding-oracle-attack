import csv
import hashlib
import hmac
from collections import Counter
from pathlib import Path
from unittest.mock import Mock

import pytest

from padding_oracle.core.contracts import BLOCK_SIZE
from padding_oracle.core.fakes import (
    FakePerfectOracle,
    fake_cbc_decrypt_raw,
    fake_cbc_encrypt,
    stub_attack,
)
from padding_oracle.countermeasures.servers import (
    AesGcmServer,
    AuthenticationError,
    EncryptThenMacServer,
)
from padding_oracle.harness.evaluation import (
    ExperimentCase,
    run_experiment,
)

ROOT = Path(__file__).parents[1]


def test_wordlist_has_expected_counts_sort_order_and_splits():
    with (ROOT / "data" / "wordlist" / "words8.csv").open(
        encoding="utf-8", newline=""
    ) as source:
        rows = list(csv.DictReader(source))

    assert len(rows) == 36_322
    assert [row["word"] for row in rows] == sorted(row["word"] for row in rows)
    assert Counter(row["band"] for row in rows) == {
        "A": 12_750, "B": 6_747, "C": 8_331, "D": 8_494
    }
    assert Counter((row["band"], row["split"]) for row in rows) == {
        ("A", "train"): 8_925, ("A", "dev"): 1_275, ("A", "test"): 2_550,
        ("B", "train"): 4_723, ("B", "dev"): 675, ("B", "test"): 1_349,
        ("C", "train"): 5_832, ("C", "dev"): 833, ("C", "test"): 1_666,
        ("D", "train"): 5_946, ("D", "dev"): 849, ("D", "test"): 1_699,
    }
    assert all(
        len(row["word"]) == 8
        and row["word"].isascii()
        and row["word"].isalpha()
        and row["word"].islower()
        for row in rows
    )


def test_encrypt_then_mac_authenticates_before_decrypting(monkeypatch):
    server = EncryptThenMacServer(bytes(16), bytes(range(32)))
    envelope = server.seal(b"secret", iv=bytes(16))
    decrypt = Mock(side_effect=AssertionError("decryption ran before MAC verification"))
    monkeypatch.setattr(server, "_decrypt", decrypt)
    tampered = bytearray(envelope.ciphertext)
    tampered[0] ^= 1

    with pytest.raises(AuthenticationError, match="^authentication failed$"):
        server.open(bytes(tampered), envelope.tag)
    decrypt.assert_not_called()


def test_invalid_authenticated_requests_have_one_public_error():
    mac_key = bytes(range(32))
    etm = EncryptThenMacServer(bytes(16), mac_key)
    etm_envelope = etm.seal(b"secret", iv=bytes(16))
    etm_errors = []
    for bad_tag in (bytes(len(etm_envelope.tag)), b"bad"):
        with pytest.raises(AuthenticationError) as error:
            etm.open(etm_envelope.ciphertext, bad_tag)
        etm_errors.append(str(error.value))

    invalid_padding = bytearray(etm_envelope.ciphertext)
    invalid_padding[BLOCK_SIZE - 1] ^= 0x0A
    valid_mac = hmac.digest(mac_key, invalid_padding, hashlib.sha256)
    with pytest.raises(AuthenticationError) as padding_error:
        etm.open(bytes(invalid_padding), valid_mac)
    etm_errors.append(str(padding_error.value))
    assert etm_errors == ["authentication failed"] * 3

    gcm = AesGcmServer(bytes(16))
    gcm_envelope = gcm.seal(b"x" * 20, nonce=bytes(12))
    tampered = bytearray(gcm_envelope.ciphertext)
    tampered[-1] ^= 1
    with pytest.raises(AuthenticationError, match="^authentication failed$"):
        gcm.open(bytes(tampered), gcm_envelope.tag)


def test_stub_harness_writes_contract_csv(tmp_path):
    ciphertext = fake_cbc_encrypt(b"known plaintext", bytes(16))[:32]
    expected = fake_cbc_decrypt_raw(ciphertext)[-16:]
    output = tmp_path / "stub-results.csv"
    rows = run_experiment(
        experiment="harness_stub",
        attack_name="stub",
        oracle=FakePerfectOracle(),
        attack=stub_attack,
        cases=[ExperimentCase("sample", ciphertext, expected)],
        seed=42,
        output_path=output,
        n_bytes=16,
    )

    assert rows[0]["queries"] == 1
    assert rows[0]["success"] == 0
    with output.open(encoding="utf-8", newline="") as result_file:
        reader = csv.DictReader(result_file)
        assert reader.fieldnames == [
            "experiment", "attack", "oracle", "seed", "target", "band",
            "bytes_attacked", "queries", "success", "params",
        ]
        assert next(reader)["success"] == "0"
