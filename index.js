const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { BadTable } = require("badb");
const { optparser } = require("gxlg-utils");
const { authenticator } = require("otplib");
const qrcode = require("qrcode");

authenticator.options = { "window": 1 };

const parser = optparser([
  { "name": "cookie",      "types": ["token"]                         },
  { "name": "path",        "types": [""],            "required": true },
  { "name": "secure",      "types": [true]                            },
  { "name": "verify",      "types": [false]                           },
  { "name": "otp",         "types": [false, ""]                       },
  { "name": "reset",       "types": [false]                           },
  { "name": "username",    "types": ["username"]                      },
  { "name": "whitelist",   "types": [false]                           },
  { "name": "jwt",         "types": ["", []],        "required": true },
  { "name": "aes",         "types": ["", []],        "required": true },
  { "name": "hmac",        "types": ["", []],        "required": true },
  { "name": "cloudflared", "types": [false]                           },
  { "name": "admin",       "types": [false, ""]                       },
  { "name": "adminCreate", "types": [false, () => {}, async () => {}] }
]);

// states:

// without whitelist:
//   verify token | reset flag | meaning               | can switch to
//   (account doesn't exist)     (0)                     2
//   absent         absent       normal account (1)      4
//   exists         absent       new account (2)         1, 2
//   absent         exists       await new register (3)  2
//   exists         exists       reset requested (4)     1, 3

// with whitelist:
// admin has to add account manually,
// invitation link is sent with preset username and verify token
// the account is created with empty password (can't login)
// can only register if account exists and valid token
//   verify token | reset flag | meaning               | can switch to
//   (account doesn't exist)     (0)                     -
//   absent         absent       normal account (1)      4
//   exists         absent       new account (2)         1
//   absent         exists       await new register (3)  2
//   exists         exists       reset requested (4)     1, 3

module.exports = (opt = {}) => {
  const options = parser(opt);

  if (options.reset && !options.verify) {
    throw new Error("Option 'reset' can not be selected without option 'verify'");
  }
  if (options.whitelist && !options.verify) {
    throw new Error("Option 'whitelist' can not be selected without option 'verify'");
  }
  if (options.whitelist && (!options.admin || !options.adminCreate)) {
    throw new Error("Option 'whitelist' can not be selected without options 'admin' and 'adminCreate'");
  }

  const jwtSecret = Buffer.from(options.jwt);
  const aesKey = Buffer.from(options.aes);
  const hmacKey = Buffer.from(options.hmac);
  const DURATION = 10 * 24 * 60 * 60 * 1000; // 10 days
  const FPLEN = 3;
  const FPOLD = 2 * 60 * 60 * 1000; // 2 hours

  function hmac(username) {
    return crypto.createHmac("sha256", hmacKey)
      .update(username).digest("base64url");
  }

  function setJWT(res, p) {
    const token = jwt.sign(p, jwtSecret, { "expiresIn": DURATION.toString() });
    const opt = {
      "httpOnly": true,
      "sameSite": true,
      "secure": options.secure,
      "maxAge": DURATION
    };
    res.cookie(options.cookie, token, opt);
  }

  function createJWT(req, res) {
    const username = req.body[options.username];

    // if the login happens with an invalid fingerprint,
    // but valid auth, then just update fingerprint
    if (verifyJWT(req, res, username)) return;

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
    let enc = cipher.update(username, "utf8", "base64url");
    enc += cipher.final("base64url");
    const tag = cipher.getAuthTag().toString("base64url"); // integrity
    const ip = hmac(options.cloudflared ? req.headers["cf-connecting-ip"] : req.ip);
    const ts = Date.now();
    const p = {
      // user data encryption
      "u": enc, "iv": iv.toString("base64url"), tag,
      // fingerprint verification
      "fp": [ip], ts
    };
    setJWT(res, p);
    req.auth = username;
  }

  function verifyJWT(req, res, username) {
    const t = req.cookies[options.cookie];
    if (t == null) return false;
    try {
      const { u, iv, tag, fp, ts } = jwt.verify(t, jwtSecret);

      // fingerprint verification
      let update = null;
      const ip = hmac(options.cloudflared ? req.headers["cf-connecting-ip"] : req.ip);
      if (!fp.includes(ip)) {
        const nts = Date.now();
        if (nts - ts > FPOLD) return false;
        else {
          // update fingerprint
          fp.push(ip);
          if (fp.length > FPLEN) fp.shift();
          update = { u, iv, tag, fp, "ts": nts };
        }
      }

      const div = Buffer.from(iv, "base64url");
      const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, div);
      decipher.setAuthTag(Buffer.from(tag, "base64url"));
      let dec = decipher.update(u, "base64url", "utf8");
      dec += decipher.final("utf8");

      if (username == null || dec == username) {
        if (update != null) setJWT(res, update);
        req.auth = dec;
        return true;
      }
    } catch { }
    return false;
  }

  const db = new BadTable(options.path, {
    "key": "u",
    "values": [
      { "name": "u", "maxLength": 43 },
      { "name": "h", "maxLength": 60 },
      ...(options.otp    ? [{ "name": "o", "maxLength": 26 }] : []),
      ...(options.reset  ? [{ "name": "r", "type": "uint8" }] : []),
      ...(options.verify ? [{ "name": "t", "maxLength": 20 }] : [])
    ]
  });

  // admin registration
  if (options.whitelist) {
    db[hmac(options.admin)]((x, c) => {
      if (c.exists() && x.h != "") return;
      x.h = "";
      const v = crypto.randomBytes(15).toString("base64url");
      x.t = v;
      options.adminCreate(v);
    });
  }

  const plugin = async (req, res) => {
    verifyJWT(req, res);

    req.login = async () => {
      const u = hmac(req.body[options.username]);
      const p = req.body.password;
      const v = req.body.verify;
      const otp = req.body.otp;
      const success = await db[u](async (x, c) => {
        if (c.exists()) {
          // state check
          if (x.t && x.r) {
            // reset requested, can login, token irrelevant
          } else if (x.t && !x.r) {
            // new account, can login only with valid token
            if (v != x.t) return false;
          } else if (!x.t && x.r) {
            // reset confirmed, can't login
            return false;
          } else {
            // normal account, can login, token irrelevant
          }
        } else return false; // can't login

        // login process
        if (!(await bcrypt.compare(p, x.h))) return false;
        if (options.otp) {
          if (!authenticator.check(otp, x.o)) return false;
        }
        if (options.verify) { x.t = ""; }
        if (options.reset) { x.r = 0; }

        return true;
      });
      if (!success) return false;
      createJWT(req, res);
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
      const ru = req.body[options.username];
      const u = hmac(ru);
      const h = await bcrypt.hash(req.body.password, 10);
      const v = req.body.verify;
      return await db[u](async (x, c) => {
        if (c.exists()) {
          // state check
          if (x.t && x.r) {
            // reset requested, can't register
            return false;
          } else if (x.t && !x.r) {
            // new account, can register again if not whitelist
            // if whitelist: only with valid token and empty password
            if (options.whitelist && (x.t != v || x.h != "")) return false;
          } else if (!x.t && x.r) {
            // reset confirmed, can register again
          } else {
            // normal account, can't register again
            return false;
          }
        } else {
          // not exists, can't register if whitelist is enabled
          if (options.whitelist) return false;
        }

        const opt = {
          "old": {
            "t": x.t,
            "h": x.h,
            "r": x.r
          }
        };

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
          const uri = authenticator.keyuri(ru, options.otp, s);
          opt.qrcode = await qrcode.toDataURL(uri);
        }
        if (options.reset) { x.r = 0; }
        return opt;
      });
    };

    req.requestReset = async () => {
      if (!options.reset) {
        throw new Error("'reset' was not enabled in the options");
      }
      const u = hmac(req.body[options.username]);
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
      if (!options.reset) {
        throw new Error("'reset' was not enabled in the options");
      }
      const u = hmac(req.body[options.username]);
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
            // normal account, reset not requested, can't start reset
            return false;
          }
        } else return false;

        // init reset process
        x.h = "";
        x.t = "";
        x.r = 1;
        return true;
      });
    };

    req.changePassword = async () => {
      if (req.auth == null) return false;
      const u = hmac(req.auth);
      const p = req.body["current-password"];
      const n = await bcrypt.hash(req.body.password, 10);
      const otp = req.body.otp;
      return await db[u](async (x, c) => {
        if (!(await bcrypt.compare(p, x.h))) return false;
        if (options.otp) {
          if (!authenticator.check(otp, x.o)) return false;
        }
        x.h = n;
        return true;
      });
    };

    req.updateOtp = async () => {
      if (!options.otp) {
        throw new Error("'otp' was not enabled in the options");
      }
      if (req.auth == null) return false;
      const ru = req.auth;
      const u = hmac(ru);
      const p = req.body.password;
      return await db[u](async (x, c) => {
        if (!(await bcrypt.compare(p, x.h))) return false;

        // generate new secret
        const opt = { };
        const s = authenticator.generateSecret(16);
        opt.old = x.o;
        x.o = s;
        opt.secret = s;
        const uri = authenticator.keyuri(ru, options.otp, s);
        opt.qrcode = await qrcode.toDataURL(uri);
        return opt;
      });
    };

    // warning: following endpoints should be called
    // only by admin or by internal error handling

    req.revertOtp = async old => {
      if (!options.otp) {
        throw new Error("'otp' was not enabled in the options");
      }
      if (req.auth == null) return false;
      const u = hmac(req.auth);
      return await db[u](async (x, c) => {
        x.o = old;
        return true;
      });
    };

    req.addWhitelist = async () => {
      if (!options.whitelist) {
        throw new Error("'whitelist' was not enabled in the options");
      }
      const u = hmac(req.body[options.username]);
      return await db[u](async (x, c) => {
        if (c.exists() && x.h != "") return false;
        x.h = "";
        const v = crypto.randomBytes(15).toString("base64url");
        x.t = v;
        return { "verify": v };
      });
    };

    req.revertWhitelist = async () => {
      if (!options.whitelist) {
        throw new Error("'whitelist' was not enabled in the options");
      }
      const u = hmac(req.body[options.username]);
      await db[u](async (x, c) => c.remove());
    }

    req.revertRegister = async old => {
      const u = hmac(req.body[options.username]);
      return await db[u](async (x, c) => {
        x.t = old.t;
        x.h = old.h;
        x.r = old.r;
      });
    };

  };

  return noptions => {
    const prev = noptions.hook;
    noptions.hook = async (req, res) => {
      await plugin(req, res);
      await prev(req, res);
    };
  };
};
