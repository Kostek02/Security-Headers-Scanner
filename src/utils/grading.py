HEADER_WEIGHTS = {
    'Content-Security-Policy': 3,
    'Strict-Transport-Security': 3,
    'X-Frame-Options': 2,
    'X-Content-Type-Options': 2,
    'Referrer-Policy': 1,
    'Permissions-Policy': 1,
    'Cache-Control': 1,
    'Access-Control-Allow-Origin': 1,
}

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