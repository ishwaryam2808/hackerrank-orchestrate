import re
import unicodedata

STRICT_NON_DELETION = [
    r"\b(copy of my personal data|export my data|download my data|data export|data portability|subject access request|sar)\b",
    r"\b(marketing emails|newsletter|unsubscribe|opt[ -]?out|stop promotional)\b",
]

DELETION_TERMS = [
    r"delet", r"eras", r"purg", r"remov", r"wip", r"close", r"destroy", r"disconnect",
    r"forget", r"right to be forgotten", r"rtbf", r"supprim", r"suppression", r"effac", r"définitif", r"definitif",
    r"lösch", r"loesch", r"entfern", r"elimin", r"apag", r"borr", r"suprim", r"cancell",
    r"削除", r"消去", r"删除", r"注销", r"удалит",
    # Audit verification phrases
    r"check", r"verify", r"inspect", r"confirm", r"existed", r"status"
]

def classify_request(request_text: str) -> str:
    if not request_text or not request_text.strip():
        return "NOT_APPLICABLE"

    text = unicodedata.normalize("NFKD", request_text)
    text_clean = "".join([c for c in text if not unicodedata.combining(c)]).lower()
    text_clean = text_clean.replace("’", "'").replace("`", "'").strip()

    is_deletion = any(re.search(term, text_clean) for term in DELETION_TERMS)
    is_pure_non_deletion = any(re.search(term, text_clean) for term in STRICT_NON_DELETION)

    if is_deletion:
        return "DELETION"

    if is_pure_non_deletion:
        return "NOT_APPLICABLE"

    return "NOT_APPLICABLE"