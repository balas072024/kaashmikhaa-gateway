FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5013

ENV PORT=5013
ENV SECRET_KEY=change-this-in-production

CMD ["gunicorn", "--bind", "0.0.0.0:5013", "--workers", "4", "--timeout", "120", "app:app"]
