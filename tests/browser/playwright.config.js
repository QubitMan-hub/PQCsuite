const { defineConfig } = require("@playwright/test");

const python = process.env.PYTHON || "python";

module.exports = defineConfig({
  testDir: ".",
  retries: 0,
  reporter: [["list"]],
  use: { browserName: "chromium" },
  webServer: [
    { command: `${python} console_server.py`, url: "http://127.0.0.1:8900/", reuseExistingServer: false },
    { command: `${python} vpn_server.py`, url: "http://127.0.0.1:8901/", reuseExistingServer: false },
  ],
});
