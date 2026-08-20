# ServerStatus

ServerStatus is a self-contained Python server and website lookup tool.

## Render

This repository is ready for Render.

### Easiest setup

1. Upload all files in this folder to the root of a GitHub repository.
2. In Render, create a Blueprint.
3. Connect the GitHub repository.
4. Render reads `render.yaml` and creates the free `serverstatus` web service.
5. Deploy the Blueprint.

No environment variables, build edits, or Python packages are required.

The included Render configuration binds ServerStatus to `0.0.0.0` and Render's `PORT` automatically.

## Local Windows

1. Install Python 3 if it is not already installed.
2. Double-click `start.bat`.
3. Your browser opens to `http://127.0.0.1:3000`.
4. Keep the command window open while ServerStatus is running.

There are no pip packages to install.

## macOS / Linux

Run:

```bash
python3 server.py
```

or:

```bash
./start.sh
```
