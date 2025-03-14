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
  { "name": "param",    "types": ["username"]                }
]);

module.exports = (opt = {}) => {
  const options = parser(opt);

  const db = new BadTable(options.path, {
    "key": "u",
    "values": [
      { "name": "u", "maxLength": options.username },
      { "name": "h", "maxLength": 60 },
      ...(options.otp    ? [{ "name": "o", "maxLength": 26 }] : []),
      ...(options.verify ? [{ "name": "t", "maxLength": 20 }] : [])
    ]
  });

  const DURATION = 30 * 24 * 60 * 60 * 1000; // 30 days

  return async (req, res) => {
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

      const success = await db[u](x => {
        if (!x.h) return false;
        if (!bcrypt.compareSync(p, x.h)) return false;
        if (options.verify && x.t) {
          if (v == x.t) { x.t = ""; }
          else return false;
        }
        if (options.otp) {
          if (!authenticator.check(otp, x.o)) return false;
        }
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
        if (c.exists() && !x.t) return null;
        x.h = h;
        const opt = {};
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
        return opt;
      });
    };
  };
};
