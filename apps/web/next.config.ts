import type { NextConfig } from "next";
import { withWorkflow } from "workflow/next";

const nextConfig: NextConfig = {
  outputFileTracingIncludes: {
    "/api/**/*": [
      "./packages/sandbox/src/**/*",
      "../../packages/sandbox/src/**/*",
    ],
  },
};

export default withWorkflow(nextConfig);
