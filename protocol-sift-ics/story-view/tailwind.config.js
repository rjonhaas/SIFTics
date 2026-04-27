/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
      colors: {
        tactic: {
          initial_access: "#dc2626",
          execution: "#ea580c",
          persistence: "#d97706",
          privilege_escalation: "#ca8a04",
          defense_evasion: "#65a30d",
          credential_access: "#16a34a",
          discovery: "#0891b2",
          lateral_movement: "#0284c7",
          collection: "#2563eb",
          command_and_control: "#7c3aed",
          exfiltration: "#c026d3",
          impact: "#be185d",
        },
      },
    },
  },
  plugins: [],
};
