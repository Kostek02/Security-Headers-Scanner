import json

# Load header weights from scan_rules.json
with open('src/data/scan_rules.json', 'r') as f:
    rules = json.load(f)
HEADER_WEIGHTS = {h['name']: h['weight'] for h in rules['headers']}

GRADE_THRESHOLDS = [
    (9, 'A'),
    (7, 'B'),
    (5, 'C'),
    (3, 'D'),
    (0, 'F'),
]

def grade_headers(headers):
    score = 0
    max_score = sum(HEADER_WEIGHTS.values())
    missing = []
    for h, weight in HEADER_WEIGHTS.items():
        if headers.get(h):
            score += weight
        else:
            missing.append(h)
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade, missing, score, max_score
    return 'F', missing, score, max_score 