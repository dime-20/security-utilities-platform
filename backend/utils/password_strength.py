import math
import string


def calculate_entropy(password: str) -> float:
    pool = 0

    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)

    if pool == 0:
        return 0.0

    entropy = len(password) * math.log2(pool)
    return round(entropy, 2)


def crack_time_from_entropy(entropy: float) -> str:
    guesses_per_second = 1e9  # offline attack
    total_guesses = 2 ** entropy
    seconds = total_guesses / guesses_per_second

    units = [
        ("seconds", 60),
        ("minutes", 60),
        ("hours", 24),
        ("days", 365),
        ("years", 100),
        ("centuries", None)
    ]

    value = seconds
    for name, limit in units:
        if limit is None or value < limit:
            return f"{int(value)} {name}"
        value /= limit

    return "infinite"


def score_from_entropy(entropy: float) -> int:
    # 0–100 scale, capped
    score = min(int(entropy * 1.5), 100)
    return score
