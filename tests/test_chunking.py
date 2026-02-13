from mimir.chunking import chunk_text


def test_chunking_deterministic():
    text = "a" * 2500
    chunks1 = chunk_text(text, source_uri="local://test", max_chars=1000, overlap=100)
    chunks2 = chunk_text(text, source_uri="local://test", max_chars=1000, overlap=100)

    assert [c.chunk_id for c in chunks1] == [c.chunk_id for c in chunks2]
    assert chunks1[0].start_offset == 0
    assert chunks1[0].end_offset == 1000
    assert chunks1[1].start_offset == 900
    assert chunks1[-1].end_offset == len(text)
