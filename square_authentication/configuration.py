import os
import sys

from square_commons import ConfigReader
from square_database_helper import SquareDatabaseHelper
from square_file_store_helper import SquareFileStoreHelper
from square_logger.main import SquareLogger

try:
    config_file_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data", "config.ini"
    )
    config_sample_file_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data", "config.sample.ini"
    )
    ldict_configuration = ConfigReader(
        config_file_path, config_sample_file_path
    ).read_configuration()

    # get all vars and typecast
    # ===========================================
    # general
    config_str_module_name = ldict_configuration["GENERAL"]["MODULE_NAME"]
    # ===========================================

    # ===========================================
    # environment
    config_str_host_ip = ldict_configuration["ENVIRONMENT"]["HOST_IP"]
    config_int_host_port = int(ldict_configuration["ENVIRONMENT"]["HOST_PORT"])
    config_list_allow_origins = eval(
        ldict_configuration["ENVIRONMENT"]["ALLOW_ORIGINS"]
    )
    config_str_log_file_name = ldict_configuration["ENVIRONMENT"]["LOG_FILE_NAME"]
    config_str_secret_key_for_access_token = ldict_configuration["ENVIRONMENT"][
        "SECRET_KEY_FOR_ACCESS_TOKEN"
    ]
    config_str_secret_key_for_refresh_token = ldict_configuration["ENVIRONMENT"][
        "SECRET_KEY_FOR_REFRESH_TOKEN"
    ]
    config_int_access_token_valid_minutes = int(
        ldict_configuration["ENVIRONMENT"]["ACCESS_TOKEN_VALID_MINUTES"]
    )
    config_int_refresh_token_valid_minutes = int(
        ldict_configuration["ENVIRONMENT"]["REFRESH_TOKEN_VALID_MINUTES"]
    )
    config_str_ssl_crt_file_path = ldict_configuration["ENVIRONMENT"][
        "SSL_CRT_FILE_PATH"
    ]
    config_str_ssl_key_file_path = ldict_configuration["ENVIRONMENT"][
        "SSL_KEY_FILE_PATH"
    ]
    config_str_db_ip = ldict_configuration["ENVIRONMENT"]["DB_IP"]

    config_int_db_port = int(ldict_configuration["ENVIRONMENT"]["DB_PORT"])

    config_str_db_username = ldict_configuration["ENVIRONMENT"]["DB_USERNAME"]

    config_str_db_password = ldict_configuration["ENVIRONMENT"]["DB_PASSWORD"]
    # ===========================================

    # ===========================================
    # square_logger
    config_int_log_level = int(ldict_configuration["SQUARE_LOGGER"]["LOG_LEVEL"])
    config_str_log_path = ldict_configuration["SQUARE_LOGGER"]["LOG_PATH"]
    config_int_log_backup_count = int(
        ldict_configuration["SQUARE_LOGGER"]["LOG_BACKUP_COUNT"]
    )
    # ===========================================

    # ===========================================
    # square_database_helper

    config_str_square_database_protocol = ldict_configuration["SQUARE_DATABASE_HELPER"][
        "SQUARE_DATABASE_PROTOCOL"
    ]
    config_str_square_database_ip = ldict_configuration["SQUARE_DATABASE_HELPER"][
        "SQUARE_DATABASE_IP"
    ]
    config_int_square_database_port = int(
        ldict_configuration["SQUARE_DATABASE_HELPER"]["SQUARE_DATABASE_PORT"]
    )
    # ===========================================

    # ===========================================
    # square_file_store_helper

    config_str_square_file_store_protocol = ldict_configuration[
        "SQUARE_FILE_STORE_HELPER"
    ]["SQUARE_FILE_STORE_PROTOCOL"]
    config_str_square_file_store_ip = ldict_configuration["SQUARE_FILE_STORE_HELPER"][
        "SQUARE_FILE_STORE_IP"
    ]
    config_int_square_file_store_port = int(
        ldict_configuration["SQUARE_FILE_STORE_HELPER"]["SQUARE_FILE_STORE_PORT"]
    )
    # ===========================================

    # ===========================================
    # EMAIL

    MAIL_GUN_API_KEY = ldict_configuration["EMAIL"]["MAIL_GUN_API_KEY"]
    # ===========================================
    # ===========================================
    # GOOGLE

    GOOGLE_AUTH_PLATFORM_CLIENT_ID = ldict_configuration["GOOGLE"][
        "GOOGLE_AUTH_PLATFORM_CLIENT_ID"
    ]
    # ===========================================
    # ===========================================
    # GOOGLE

    NUMBER_OF_RECOVERY_CODES = int(
        ldict_configuration["LOGIC"]["NUMBER_OF_RECOVERY_CODES"]
    )
    EXPIRY_TIME_FOR_EMAIL_VERIFICATION_CODE_IN_SECONDS = int(
        ldict_configuration["LOGIC"][
            "EXPIRY_TIME_FOR_EMAIL_VERIFICATION_CODE_IN_SECONDS"
        ]
    )
    NUMBER_OF_DIGITS_IN_EMAIL_VERIFICATION_CODE = int(
        ldict_configuration["LOGIC"]["NUMBER_OF_DIGITS_IN_EMAIL_VERIFICATION_CODE"]
    )
    EXPIRY_TIME_FOR_EMAIL_PASSWORD_RESET_CODE_IN_SECONDS = int(
        ldict_configuration["LOGIC"][
            "EXPIRY_TIME_FOR_EMAIL_PASSWORD_RESET_CODE_IN_SECONDS"
        ]
    )
    NUMBER_OF_DIGITS_IN_EMAIL_PASSWORD_RESET_CODE = int(
        ldict_configuration["LOGIC"]["NUMBER_OF_DIGITS_IN_EMAIL_PASSWORD_RESET_CODE"]
    )
    # ===========================================

    # Initialize logger
    global_object_square_logger = SquareLogger(
        pstr_log_file_name=config_str_log_file_name,
        pint_log_level=config_int_log_level,
        pstr_log_path=config_str_log_path,
        pint_log_backup_count=config_int_log_backup_count,
    )
    global_object_square_database_helper = SquareDatabaseHelper(
        param_str_square_database_ip=config_str_square_database_ip,
        param_int_square_database_port=config_int_square_database_port,
        param_str_square_database_protocol=config_str_square_database_protocol,
    )
    global_object_square_file_store_helper = SquareFileStoreHelper(
        param_str_square_file_store_protocol=config_str_square_file_store_protocol,
        param_str_square_file_store_ip=config_str_square_file_store_ip,
        param_int_square_file_store_port=config_int_square_file_store_port,
    )
except Exception as e:
    print(
        "\033[91mMissing or incorrect config.ini file.\n"
        "Error details: " + str(e) + "\033[0m"
    )
    sys.exit()
