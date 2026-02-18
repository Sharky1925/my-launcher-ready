module.exports = {
  run: [{
    method: "shell.run",
    params: {
      venv: "env",
      path: "app",
      message: [
        "uv pip install -r requirements.txt"
      ]
    }
  }, {
    method: "fs.write",
    params: {
      path: "app/.installed",
      text: "ok\n"
    }
  }]
}
