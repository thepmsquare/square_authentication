import random
import string
from typing import Optional

from square_database_helper import FiltersV0
from square_database_helper.pydantic_models import FilterConditionsV0
from square_database_structure.square import global_string_database_name
from square_database_structure.square.authentication import global_string_schema_name
from square_database_structure.square.authentication.tables import User

from square_authentication.configuration import global_object_square_database_helper


def generate_default_username_for_google_users(given_name: Optional[str], family_name: Optional[str]) -> str:

    given = given_name.lower() if given_name else "user"
    family = family_name.lower() if family_name else "user"

    # sanitize (keep a-z, 0-9, _, -)
    allowed_chars = set(string.ascii_lowercase + string.digits + "_-")
    given = "".join(c for c in given if c in allowed_chars)
    family = "".join(c for c in family if c in allowed_chars)

    while True:
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        username_candidate = f"{given}_{family}_{random_suffix}"

        # check uniqueness
        existing = global_object_square_database_helper.get_rows_v0(
            database_name=global_string_database_name,
            schema_name=global_string_schema_name,
            table_name=User.__tablename__,
            filters=FiltersV0(root={User.user_username.name: FilterConditionsV0(eq=username_candidate)}),
        )["data"]["main"]

        if not existing:
            return username_candidate
