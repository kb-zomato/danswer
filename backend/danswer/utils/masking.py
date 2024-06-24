import json
import subprocess
import tempfile
import os
from danswer.utils.logger import setup_logger
from trufflehog3.core import load_rules, DEFAULT_RULES_FILE
from trufflehog3.search import search
from trufflehog3.models import File

logger = setup_logger()

def find_and_mask_secrets(text):
   return find_and_mask_by_trufflehog(text)

def find_and_mask_by_trufflehog(text):
    file = File(path="temp", content=text)
    issues = search(file, rules=load_rules(DEFAULT_RULES_FILE))
    masked_text = text
    secret_values: list[str] = []
    for issue in issues:
        secret_value = issue.secret
        secret_values.append(secret_value)
        masked_text = masked_text.replace(secret_value, '[MASKED]')
    
    if len(secret_values) > 0:
        logger.info(f"Found and masked {secret_values} in {text}")
    
    return masked_text


if __name__ == "__main__":   
    print(find_and_mask_secrets("password = 'abcdefghijklmnopqrstuvwxyz'"))
