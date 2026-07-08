import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// Works both from src/ (via tsx) and from dist/ — package.json is one level up.
export const VERSION: string = (require("../package.json") as { version: string }).version;
