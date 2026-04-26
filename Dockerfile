FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY meok_dora_tlpt_planner ./meok_dora_tlpt_planner
RUN pip install --no-cache-dir .
EXPOSE 8000
CMD ["python", "-m", "meok_dora_tlpt_planner"]
