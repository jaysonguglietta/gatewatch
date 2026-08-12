import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  output: process.env.GATEWATCH_TARGET === "aws" ? "standalone" : undefined,
  webpack(config, { webpack }) {
    if (process.env.GATEWATCH_TARGET === "aws") {
      config.plugins.push(
        new webpack.NormalModuleReplacementPlugin(
          /^cloudflare:workers$/,
          path.resolve(process.cwd(), "lib/aws-cloudflare-workers.ts"),
        ),
      );
    }
    return config;
  },
};

export default nextConfig;
