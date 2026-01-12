from pydantic import BaseModel


class GetTextHashV0Response(BaseModel):
    main: str
