from fastapi.testclient import TestClient
from square_commons import get_api_output_in_standard_format

from square_authentication.configuration import config_str_module_name
from square_authentication.main import (
    app,
)

client = TestClient(app)


def test_read_main():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == get_api_output_in_standard_format(
        log=config_str_module_name
    )
