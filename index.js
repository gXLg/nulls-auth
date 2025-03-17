const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { BadTable } = require("badb");
const { optparser } = require("gxlg-utils");
const { authenticator } = require("otplib");
const qrcode = require("qrcode");

authenticator.options = { "window": 1 };

const parser = optparser([
  { "name": "cookie",   "types": ["token"]                   },
  { "name": "path",     "types": [""],      "required": true },
  { "name": "secret",   "types": [""],      "required": true },
  { "name": "username", "types": [24]                        },
  { "name": "secure",   "types": [true]                      },
  { "name": "verify",   "types": [false]                     },
  { "name": "otp",      "types": [false, ""]                 },
  { "name": "reset",    "types": [false]                     },
  { "name": "param",    "types": ["username"]                }
]);

// states:
// verify token | reset flag | meaning               | can switch to
// absent         absent       normal account (1)      4
// exists         absent       new account (2)         1, 2
// absent         exists       await new register (3)  2
// exists         exists       reset requested (4)     1, 3

module.exports = (opt = {}) => {
  const options = parser(opt);

  if (options.reset && !options.verify) {
    throw new Error("Option 'reset' can not be selected without option 'verify'");
  }

  const db = new BadTable(options.path, {
    "key": "u",
    "values": [
      { "name": "u", "maxLength": options.username },
      { "name": "h", "maxLength": 60 },
      ...(options.otp    ? [{ "name": "o", "maxLength": 26 }] : []),
      ...(options.reset  ? [{ "name": "r", "type": "uint8" }] : []),
      ...(options.verify ? [{ "name": "t", "maxLength": 20 }] : [])
    ]
  });

  const DURATION = 30 * 24 * 60 * 60 * 1000; // 30 days

  const plugin = async (req, res) => {
    const token = req.cookies[options.cookie];
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
      const u = req.body[options.param];
      const p = req.body.password;
      const v = req.body.verify;
      const otp = req.body.otp;
      const success = await db[u]((x, c) => {
        if (c.exists()) {
          // state check
          if (x.t && x.r) {
            // reset requested, can login, token irrelevant
          } else if (x.t && !x.r) {
            // new account, can login only with token
            if (v != x.t) return false;
          } else if (!x.t && x.r) {
            // reset confirmed, can't login
            return false;
          } else {
            // normal account, can login, token irrelevant
          }
        } else return false; // can't login

        // login process
        if (!bcrypt.compareSync(p, x.h)) return false;
        if (options.verify) { x.t = ""; }
        if (options.otp) {
          if (!authenticator.check(otp, x.o)) return false;
        }
        if (options.reset) { x.r = 0; }

        return true;
      });
      if (!success) return false;

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
      const u = req.body[options.param];
      const p = req.body.password;
      const h = bcrypt.hashSync(p);
      return await db[u](async (x, c) => {
        if (c.exists()) {
          // state check
          if (x.t && x.r) {
            // reset requested, can't register
            return false;
          } else if (x.t && !x.r) {
            // new account, can register again
          } else if (!x.t && x.r) {
            // reset confirmed, can register again
          } else {
            // normal account, can't register again
            return false;
          }
        }

        const opt = { };
        // register process
        x.h = h;
        if (options.verify) {
          const v = crypto.randomBytes(15).toString("base64url");
          x.t = v;
          opt.verify = v;
        }
        if (options.otp) {
          const s = authenticator.generateSecret(16);
          x.o = s;
          opt.secret = s;
          const uri = authenticator.keyuri(u, options.otp, s);
          opt.qrcode = await qrcode.toDataURL(uri);
        }
        if (options.reset) { x.r = 0; }
        return opt;
      });
    };

    req.requestReset = async () => {
      const u = req.body[options.param];
      return await db[u](async (x, c) => {
        if (c.exists()) {
          // state check
          if (x.t && x.r) {
            // reset requested, can request again
          } else if (x.t && !x.r) {
            // new account, can't request reset
            return false;
          } else if (!x.t && x.r) {
            // reset confirmed, can't request reset
            return false;
          } else {
            // normal account, can request reset
          }
        } else return false;

        const opt = { };
        // request reset process
        const v = crypto.randomBytes(15).toString("base64url");
        x.t = v;
        opt.verify = v;
        x.r = 1;
        return opt;
      });
    };

    req.confirmReset = async () => {
      const u = req.body[options.param];
      const v = req.body.verify;
      return await db[u](async (x, c) => {
        if (c.exists()) {
          // state check
          if (x.t && x.r) {
            // reset requested, can start reset with valid token
            if (v != x.t) return false;
          } else if (x.t && !x.r) {
            // new account, can't start reset
            return false;
          } else if (!x.t && x.r) {
            // reset confirmed, can't start reset again
            return false;
          } else {
            // normal account, can't start reset
            return false;
          }
        } else return false;

        // init reset process
        x.t = "";
        x.r = 1;
        return true;
      });
    };
  };

  return options => {
    const prev = options.hook;
    options.hook = async (req, res) => {
      await plugin(req, res);
      await prev(req, res);
    };
  };
};
