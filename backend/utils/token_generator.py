import secrets
import string

CHARSETS = {
    "letters": string.ascii_letters,
    "digits": string.digits,
    "specials": string.punctuation,
}

def generate_token(length: int, charset_key: str) -> str:
    parts = charset_key.split(",")
    charset = ""

    for part in parts:
        part = part.strip()
        if part not in CHARSETS:
            raise ValueError("Invalid charset")
        charset += CHARSETS[part]

    if not charset:
        raise ValueError("Empty charset")

    return "".join(secrets.choice(charset) for _ in range(length))
