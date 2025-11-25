import logging
import os.path
import re

import dotenv

dotenv.load_dotenv()


logger = logging.getLogger(__name__)

def get_permissions(method_signature):
    try:
        if not os.getenv("SOURCESANDSINKSTYPES"):
            logger.error("SOURCESANDSSINKSTPYES env variable not defined, this will translate in loss of data type information...")
            return "NONE"
        with open(os.getenv("SOURCESANDSINKSTYPES"), "r") as mappings:
            for line in mappings:
                line = line.strip("")
                if line.startswith("%") or not line:
                    continue

                try:
                    match = re.match(r"<(.*)> -> _(.*)_", line)
                    if match:
                        first_part, second_part = match.groups()
                        # Check if method_signature matches the extracted first part
                        if method_signature.strip("<").strip(">") == first_part:
                            # Return the second part without "_"
                            return second_part
                except ValueError:
                    # Skip lines that don't match the format
                    continue
            # If there's no match then return NONE
            logger.warning(f"Type of method {method_signature} not found")
            return "NONE"
    except FileNotFoundError:
        logger.error("Sources and Sinks type file not found, this will translate in loss of data type information")
        return "NONE"

