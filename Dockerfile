FROM python:3.12-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && \
    apt-get install -y curl && \
    pip install --upgrade pip && \
    pip install uv

# Copy the application code
COPY . .

# Install the application using uv sync
RUN uv sync && \
    uv add gunicorn fastmcp

EXPOSE 5050 5051

# Default command is to run the application
CMD ["uv", "run", "python", "run.py"]