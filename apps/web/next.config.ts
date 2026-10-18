import type { NextConfig } from "next";
import { withWorkflow } from "workflow/next";

const nextConfig: NextConfig = {
  env: {
    CLOUDFLARE_WORKER_URL: "https://shipsafe.dhruvilmistry16.workers.dev",
  },
  outputFileTracingIncludes: {
    "/api/**/*": [
      "./packages/sandbox/src/**/*",
      "../../packages/sandbox/src/**/*",
    ],
  },
};

export default withWorkflow(nextConfig);
