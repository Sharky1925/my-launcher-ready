module.exports = {
  run: [{
    method: "fs.rm",
    params: {
      path: "app/env"
    }
  }, {
    method: "fs.rm",
    params: {
      path: "app/site.db"
    }
  }, {
    method: "fs.rm",
    params: {
      path: "app/uploads"
    }
  }, {
    method: "fs.rm",
    params: {
      path: "app/.installed"
    }
  }]
}
