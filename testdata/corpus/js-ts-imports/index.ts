import lodash from "lodash";
import * as fs from "fs";
import "./local-file";
require("express");
import("axios");

// Adversarial import tests
import defaultVal from "pkg-default";
import type { x } from "pkg-type";
export * from "pkg-export-all";
export { y } from "pkg-export-some";
const req = require("pkg-require");
const dyn = import("pkg-dynamic");
import x from "@scope/pkg-scoped";

// Ignore Node built-ins
import path from "node:path";
import crypto from "crypto";

// Flag unresolved dynamic import
const varName = "some-pkg";
require(varName);
