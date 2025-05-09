from square_commons import get_api_output_in_standard_format


def test_read_main(get_patched_configuration, create_client_and_cleanup):
    client = create_client_and_cleanup
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == get_api_output_in_standard_format(
        log=get_patched_configuration.config_str_module_name
    )
