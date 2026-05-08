FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 2121 2222 2323 8080 8443 33060 5000

# Script to run both components
RUN echo '#!/bin/bash\npython app.py & python honeypot.py & wait -n' > run.sh
RUN chmod +x run.sh

CMD ["./run.sh"]
