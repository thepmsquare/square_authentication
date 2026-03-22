import re
import string
import random
from typing import Optional

from square_authentication.configuration import global_object_square_database_helper
from square_database_helper import FiltersV0
from square_database_helper.pydantic_models import FilterConditionsV0
from square_database_structure.square import global_string_database_name
from square_database_structure.square.authentication import global_string_schema_name
from square_database_structure.square.authentication.tables import User

USERNAME_MAX_LENGTH = 20
USERNAME_RE = re.compile(rf"^[a-z0-9._-]{{2,{USERNAME_MAX_LENGTH}}}$")


def generate_default_username_for_google_users(
    given_name: Optional[str], family_name: Optional[str]
) -> str:

    given = given_name.lower() if given_name else "user"
    family = family_name.lower() if family_name else "user"

    # sanitize (keep a-z, 0-9, _, -)
    allowed_chars = set(string.ascii_lowercase + string.digits + "_-")
    given = "".join(c for c in given if c in allowed_chars)
    family = "".join(c for c in family if c in allowed_chars)

    # We have 20 chars total.
    # suffix is 6 chars + "_" = 7 chars.
    # We have 13 chars for "given_family".
    max_names_len = USERNAME_MAX_LENGTH - 6 - 1
    combined_names = f"{given}_{family}"
    if len(combined_names) > max_names_len:
        combined_names = combined_names[:max_names_len].rstrip("_").rstrip("-").rstrip(".")

    while True:
        random_suffix = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=6)
        )
        username_candidate = f"{combined_names}_{random_suffix}"

        # check uniqueness
        existing = (
            global_object_square_database_helper.get_rows_v0(
                database_name=global_string_database_name,
                schema_name=global_string_schema_name,
                table_name=User.__tablename__,
                filters=FiltersV0(
                    root={
                        User.user_username.name: FilterConditionsV0(eq=username_candidate)
                    }
                ),
                response_as_pydantic=True,
            )
            .data.main
        )

        if not existing:
            return username_candidate
