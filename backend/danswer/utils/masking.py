from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings
import tempfile
import os
from danswer.utils.logger import setup_logger

logger = setup_logger()

def find_and_mask_secrets(text):
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        tmp_file.write(text.encode())
        tmp_file_path = tmp_file.name

    # Scan the temporary file
    with default_settings() as settings:
        secrets = SecretsCollection()
        secrets.scan_file(tmp_file_path)
    
    # Read back the secrets and mask them
    masked_text = text
    secret_values: list[str] = []
    for secret in secrets:
        secret_value = secret[1].secret_value
        secret_values.append(secret_value)
        masked_text = masked_text.replace(secret_value, '[MASKED]')
    
    if len(secret_values) > 0:
        logger.info(f"Found and masked {secret_values} in {text}")
                    
    # Clean up the temporary file
    os.remove(tmp_file_path)
    
    return masked_text
