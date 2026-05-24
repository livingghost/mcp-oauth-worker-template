import { register } from "node:module";

register("./cloudflare-workers-test-loader.mjs", import.meta.url);
