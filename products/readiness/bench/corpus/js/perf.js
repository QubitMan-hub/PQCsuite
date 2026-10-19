const suite = require("./suite");

suite.bench("pbkdf2", () => suite.run());
suite.bench("sha256", () => suite.run());
