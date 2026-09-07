import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Cascadia Code", "ui-monospace", "monospace"],
      },
      boxShadow: {
        panel: "0 18px 50px rgba(2, 6, 23, 0.24)",
        glow: "0 0 0 1px rgba(123, 223, 242, 0.08), 0 12px 40px rgba(2, 6, 23, 0.28)",
      },
    },
  },
  plugins: [],
} satisfies Config;
