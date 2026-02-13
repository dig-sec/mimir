from mimir.llm.parse import extract_triples, parse_json_safe


def test_parse_json_safe_with_code_fence():
    raw = """```json
    {"triples": [{"subject": "Ada", "predicate": "wrote", "object": "notes", "confidence": 0.9}]}
    ```"""
    data = parse_json_safe(raw)
    assert "triples" in data


def test_extract_triples_filters_invalid():
    raw = '{"triples": [{"subject": "Ada", "predicate": "wrote", "object": "notes", "confidence": 0.9}, {"subject": "", "predicate": "x", "object": "y", "confidence": 0.2}]}'
    triples = extract_triples(raw)
    assert len(triples) == 1
    assert triples[0].subject == "Ada"
