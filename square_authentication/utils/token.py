import jwt
from jwt.exceptions import ExpiredSignatureError, DecodeError, InvalidTokenError


def get_jwt_payload(token, secret_key):
    try:
        # Decode the token and verify the signature
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        return payload
    except ExpiredSignatureError:
        raise Exception("The token has expired.")
    except DecodeError:
        raise Exception("The token is invalid.")
    except InvalidTokenError:
        raise Exception("The token is invalid.")
    except Exception:
        raise
