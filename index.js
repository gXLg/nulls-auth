const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { BadTable } = require("badb");

module.exports = (opt = {}) => {
  const args = [
    ["cookie", false, "token"],
    ["path", true, ""],
    ["secret", true, ""],
    ["username", false, 24],
    ["secure", false, true],
    ["verify", false, false]
  ];

  const options = { };
  for (const [name, required, ...def] of args) {
    const value = opt[name];
    let valid = value == null;
    if (!valid) {
      for (const d of def) {
        if (value.constructor == d.constructor) {
          valid = true;
          break;
        }
      }
    }
    if (!valid) {
      throw new Error(
        "Argument '" + name + "' has a wrong type! Expected one of: " +
        [...new Set(def.map(d => d.constructor.name))].join(", ")
      );
    }
    if (required && value == null) {
      throw new Error("Non-null argument '" + name + "' is required, but was not found");
    }
    options[name] = value ?? def[0];
  }

  const db = new BadTable(options.path, {
    "key": "u",
    "values": [
      { "name": "u", "maxLength": options.username },
      { "name": "h", "maxLength": 60 },
      ...(options.verify ? [{ "name": "t", "maxLength": 20 }] : [])
    ]
  });

  const DURATION = 30 * 24 * 60 * 60 * 1000; // 30 days

  return async (req, res) => {
    const token = res.cookies[options.cookie];
    let u = null;
    try {
      const d = jwt.verify(token, options.secret);
      if ("u" in d) {
        const [t, e] = await db[d.u]((x, c) => [x.t, c.exists()]);
        if (e && !(options.verify && t)) { u = d.u; }
      }
    } catch { }
    req.auth = u;

    req.login = async () => {
      const u = req.body.username;
      const p = req.body.password;
      const v = req.query.verify;

      const { h, t } = await db[u](x => [x.h, x.t]);
      if (!bcrypt.compareSync(p, h)) return false;
      if (options.verify && t) {
        if (v == t) await db[u](x => { x.t = ""; });
        else return false;
      }

      const token = jwt.sign({ u }, options.secret, { "expiresIn": DURATION.toString() });
      const opt = {
        "httpOnly": true,
        "sameSite": true,
        "secure": options.secure,
        "maxAge": DURATION
      };
      res.cookie(options.cookie, token, opt);
      req.auth = u;
      return true;
    };

    req.logout = async () => {
      res.clearCookie(options.cookie, {
        "httpOnly": true,
        "sameSite": true
      });
      req.auth = null;
    };

    req.register = async () => {
      const u = req.body.username;
      const p = req.body.password;
      const h = bcrypt.hashSync(p);

      return await db[u]((x, c) => {
        if (c.exists() && !x.t) return false;
        x.h = h;
        if (options.verify) {
          const v = crypto.randomBytes(15).toString("base64url");
          x.t = v;
          return v;
        }
        return true;
      });
    };
  };
};
