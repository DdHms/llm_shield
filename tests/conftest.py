import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src import constants


@pytest.fixture(autouse=True)
def restore_runtime_config():
    original_exclusions = list(constants.DEFAULT_EXCLUSIONS)
    original_mode = constants.SCRUBBING_MODE
    original_analyzer = constants.ANALYZER_TYPE
    original_target_url = constants.TARGET_URL
    original_host = constants.HOST
    original_port = constants.PORT
    original_dashboard_token = constants.DASHBOARD_TOKEN

    yield

    constants.DEFAULT_EXCLUSIONS = original_exclusions
    constants.SCRUBBING_MODE = original_mode
    constants.ANALYZER_TYPE = original_analyzer
    constants.TARGET_URL = original_target_url
    constants.HOST = original_host
    constants.PORT = original_port
    constants.DASHBOARD_TOKEN = original_dashboard_token
