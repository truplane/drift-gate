FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY policies ./policies
COPY examples ./examples

RUN pip install --no-cache-dir .

ENTRYPOINT ["drift-gate"]
CMD ["evaluate", "--plan", "examples/plan_clean.json", "--policies", "policies", "--format", "markdown"]
