FROM python:3.13-alpine
WORKDIR /app
COPY . .
ENV HOST=0.0.0.0
ENV PORT=3000
ENV NO_BROWSER=1
EXPOSE 3000
CMD ["python", "server.py"]
