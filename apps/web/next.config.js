/** @type {import('next').NextConfig} */
const nextConfig = {
  outputFileTracingIncludes: {
    "/api/**/*": [
      "./packages/sandbox/src/**/*",
      "../../packages/sandbox/src/**/*",
    ],
  },
};
module.exports = nextConfig;
