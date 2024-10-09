import { describe } from "node:test";
import assert from "node:assert";

import jsonSchemaTest from "json-schema-test-esm";
import Ajv from "ajv";
import schema from "./index.json" with { type: "json" };

const ajv = new Ajv({
  schemas: [schema],
  strictTypes: false,
});

jsonSchemaTest(ajv, {
  description: "sast-json-schema",
  suites: {
    SAST: "./tests/*.json",
  },
  cwd: import.meta.dirname,
  describe,
  assert,
});
