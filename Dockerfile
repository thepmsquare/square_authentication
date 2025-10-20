FROM ghcr.io/astral-sh/uv:python3.12-trixie-slim
WORKDIR /app
COPY . /app

RUN uv sync --locked --extra all

CMD ["uv", "run", "--", "python", "-m", "square_authentication.main"]

# Uncomment for debugging
# CMD ["bash", "-c", "while true; do sleep 60; done"]