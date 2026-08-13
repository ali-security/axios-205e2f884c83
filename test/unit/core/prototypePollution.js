"use strict";

import assert from "assert";
import http from "http";
import axios from "../../../index.js";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import defaults from "../../../lib/defaults/index.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";
import httpAdapter from "../../../lib/adapters/http.js";

const SERVER_PORT = 4449;

describe("Prototype Pollution Protection", function () {
  afterEach(function () {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
    delete Object.prototype.transport;
    delete Object.prototype.transformRequest;
    delete Object.prototype.transformResponse;
    delete Object.prototype.formSerializer;
    delete Object.prototype.env;
    delete Object.prototype.parseReviver;
    delete Object.prototype.transitional;
    delete Object.prototype.responseType;
    delete Object.prototype.response;
    delete Object.prototype.customProp;
    delete Object.prototype.headers;
  });

  describe("utils.merge", function () {
    it("should filter __proto__ key at top level", function () {
      const result = utils.merge(
        {},
        { __proto__: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key at top level", function () {
      const result = utils.merge(
        {},
        { constructor: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key at top level", function () {
      const result = utils.merge(
        {},
        { prototype: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter __proto__ key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            __proto__: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            constructor: { prototype: { polluted: "nested" } },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            prototype: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in deeply nested objects", function () {
      const result = utils.merge(
        {},
        {
          level1: {
            level2: {
              __proto__: { polluted: "deep" },
              prototype: { polluted: "deep" },
              safe: "value",
            },
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.level1.level2.safe, "value");
      assert.strictEqual(
        result.level1.level2.hasOwnProperty("__proto__"),
        false,
      );
    });

    it("should still merge regular properties correctly", function () {
      const result = utils.merge({ a: 1, b: { c: 2 } }, { b: { d: 3 }, e: 4 });

      assert.strictEqual(result.a, 1);
      assert.strictEqual(result.b.c, 2);
      assert.strictEqual(result.b.d, 3);
      assert.strictEqual(result.e, 4);
    });

    it("should handle JSON.parse payloads safely", function () {
      const malicious = JSON.parse('{"__proto__": {"polluted": "yes"}}');
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should handle nested JSON.parse payloads safely", function () {
      const malicious = JSON.parse(
        '{"headers": {"constructor": {"prototype": {"polluted": "yes"}}}}',
      );
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });
  });

  describe("mergeConfig", function () {
    it("should filter dangerous keys at top level", function () {
      const result = mergeConfig(
        {},
        {
          __proto__: { polluted: "yes" },
          constructor: { polluted: "yes" },
          prototype: { polluted: "yes" },
          url: "/api/test",
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.url, "/api/test");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in headers", function () {
      const result = mergeConfig(
        {},
        {
          headers: {
            __proto__: { polluted: "yes" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter dangerous keys in custom config properties", function () {
      const result = mergeConfig(
        {},
        {
          customProp: {
            __proto__: { polluted: "yes" },
            safe: "value",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.customProp.safe, "value");
      assert.strictEqual(result.customProp.hasOwnProperty("__proto__"), false);
    });

    it("should not inherit transport from Object.prototype", function () {
      Object.prototype.transport = { request: function () {} };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(result.hasOwnProperty("transport"), false);
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transport"),
        false
      );
    });

    it("should not inherit transformRequest from Object.prototype", function () {
      Object.prototype.transformRequest = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformRequest"),
        false
      );
    });

    it("should not inherit transformResponse from Object.prototype", function () {
      Object.prototype.transformResponse = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformResponse"),
        false
      );
    });

    it("should not inherit arbitrary keys from Object.prototype", function () {
      Object.prototype.polluted = "yes";
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "polluted"),
        false
      );
    });

    it("should not deep-merge an inherited value into a key set by the other config", function () {
      Object.prototype.customProp = { evil: "yes" };

      const result = mergeConfig({}, { customProp: { safe: "value" } });

      assert.strictEqual(result.customProp.safe, "value");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result.customProp, "evil"),
        false,
      );
    });

    it("should not deep-merge inherited headers into the request headers", function () {
      Object.prototype.headers = { Authorization: "Bearer evil" };

      const result = mergeConfig({}, { headers: { Accept: "text/plain" } });

      assert.strictEqual(result.headers.Accept, "text/plain");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result.headers, "Authorization"),
        false,
      );
    });

    it("should still merge configs correctly", function () {
      const config1 = {
        baseURL: "https://api.example.com",
        timeout: 1000,
        headers: {
          common: {
            Accept: "application/json",
          },
        },
      };

      const config2 = {
        url: "/users",
        timeout: 5000,
        headers: {
          common: {
            "Content-Type": "application/json",
          },
        },
      };

      const result = mergeConfig(config1, config2);

      assert.strictEqual(result.baseURL, "https://api.example.com");
      assert.strictEqual(result.url, "/users");
      assert.strictEqual(result.timeout, 5000);
      assert.strictEqual(result.headers.common.Accept, "application/json");
      assert.strictEqual(
        result.headers.common["Content-Type"],
        "application/json",
      );
    });
  });

  describe("defaults.transformRequest", function () {
    it("should not inherit formSerializer from Object.prototype", function () {
      Object.prototype.formSerializer = {
        visitor: function () {
          this.append("pwned", "yes");
          return false;
        },
      };

      const headers = new AxiosHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
      });

      const result = defaults.transformRequest[0].call({}, { a: "1" }, headers);

      assert.strictEqual(result, "a=1");
    });

    it("should not inherit env from Object.prototype", function () {
      let hijacked = false;

      function EvilFormData() {
        hijacked = true;
      }

      EvilFormData.prototype.append = function () {};

      Object.prototype.env = { FormData: EvilFormData };

      const headers = new AxiosHeaders({
        "Content-Type": "multipart/form-data",
      });

      const result = defaults.transformRequest[0].call({}, { a: "1" }, headers);

      assert.strictEqual(hijacked, false);
      assert.strictEqual(result instanceof EvilFormData, false);
    });
  });

  describe("defaults.transformResponse", function () {
    it("should not inherit transitional from Object.prototype", function () {
      Object.prototype.transitional = {
        silentJSONParsing: true,
        forcedJSONParsing: false,
      };

      const result = defaults.transformResponse[0].call({}, '{"a":1}');

      assert.strictEqual(typeof result, "object");
      assert.strictEqual(result.a, 1);
    });

    it("should not inherit responseType from Object.prototype", function () {
      Object.prototype.responseType = "text";

      const result = defaults.transformResponse[0].call({}, '{"a":1}');

      assert.strictEqual(typeof result, "object");
      assert.strictEqual(result.a, 1);
    });

    it("should not inherit parseReviver from Object.prototype", function () {
      Object.prototype.parseReviver = function (key, value) {
        return key ? "pwned" : value;
      };

      const result = defaults.transformResponse[0].call({}, '{"a":1}');

      assert.strictEqual(result.a, 1);
    });

    it("should not inherit response from Object.prototype", function () {
      Object.prototype.response = { status: 999 };

      let error;

      try {
        defaults.transformResponse[0].call(
          {
            transitional: {
              silentJSONParsing: false,
              forcedJSONParsing: true,
            },
            responseType: "json",
          },
          "{invalid json",
        );
      } catch (e) {
        error = e;
      }

      assert.ok(error, "expected a parsing error to be thrown");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(error, "response"),
        false,
      );
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(error, "status"),
        false,
      );
    });
  });

  describe("http adapter", function () {
    let server;
    let receivedBody;

    beforeEach(function (done) {
      receivedBody = "";

      server = http.createServer(function (req, res) {
        req.on("data", function (chunk) {
          receivedBody += chunk.toString();
        });

        req.on("end", function () {
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ real: true }));
        });
      });

      server.listen(SERVER_PORT, function () {
        done();
      });
    });

    afterEach(function (done) {
      if (!server) {
        return done();
      }

      const closing = server;
      server = null;

      if (typeof closing.closeAllConnections === "function") {
        closing.closeAllConnections();
      }

      closing.close(function () {
        done();
      });
    });

    it("should not inherit transport from Object.prototype", async function () {
      this.timeout(10000);

      Object.prototype.transport = {
        request: function () {
          throw new Error("hijacked transport was used");
        },
      };

      const { data } = await axios.get(`http://localhost:${SERVER_PORT}/`, {
        maxRedirects: 0,
      });

      assert.deepStrictEqual(data, { real: true });
    });

    it("should not inherit responseType from Object.prototype", async function () {
      this.timeout(10000);

      Object.prototype.responseType = "text";

      const { data } = await axios.get(`http://localhost:${SERVER_PORT}/`);

      assert.deepStrictEqual(data, { real: true });
    });

    it("should not inherit parseReviver from Object.prototype", async function () {
      this.timeout(10000);

      Object.prototype.parseReviver = function (key, value) {
        return key ? "pwned" : value;
      };

      const { data } = await axios.get(`http://localhost:${SERVER_PORT}/`);

      assert.deepStrictEqual(data, { real: true });
    });

    it("should not inherit formSerializer from Object.prototype", async function () {
      this.timeout(10000);

      Object.prototype.formSerializer = {
        visitor: function () {
          this.append("pwned", "yes");
          return false;
        },
      };

      await axios.post(
        `http://localhost:${SERVER_PORT}/`,
        { a: "1" },
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } },
      );

      assert.strictEqual(receivedBody, "a=1");
    });

    it("should not inherit env from Object.prototype when reading a data URL", async function () {
      if (typeof Blob === "undefined") {
        this.skip();
        return;
      }

      let hijacked = false;

      function EvilBlob() {
        hijacked = true;
      }

      Object.prototype.env = { Blob: EvilBlob };

      const buffer = Buffer.from("123");
      const dataURI =
        "data:application/octet-stream;base64," + buffer.toString("base64");

      // The adapter is called with a config that never declares `env` itself,
      // so the only way `EvilBlob` can be reached is through the prototype.
      const { data } = await httpAdapter({
        method: "get",
        url: dataURI,
        responseType: "blob",
      });

      assert.strictEqual(hijacked, false);
      assert.strictEqual(data instanceof EvilBlob, false);
      assert.strictEqual(data instanceof Blob, true);
    });
  });
});
