module.exports = {
  run: [{
    method: "shell.run",
    params: {
      venv: "env",
      path: "app",
      message: [
        "uv pip install -r requirements-dev.txt",
        "python -m pytest -q"
      ]
    }
  }]
}
