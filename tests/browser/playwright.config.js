const { defineConfig } = require("@playwright/test");

const python = process.env.PYTHON || "python";

module.exports = defineConfig({
  testDir: ".",
  retries: 0,
  reporter: [["list"]],
  use: { browserName: "chromium" },
  webServer: [
    { command: `${python} -m http.server 8765 --bind 127.0.0.1 --directory ../../site`, url: "http://127.0.0.1:8765/index.html", reuseExistingServer: false },
    { command: `${python} console_server.py`, url: "http://127.0.0.1:8900/", reuseExistingServer: false },
  ],
});
