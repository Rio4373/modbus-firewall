import animate from "tailwindcss-animate";

/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        border: "#263445",
        background: "#071019",
        foreground: "#e5edf5",
        muted: "#8b9bad",
        card: "#0d1722",
        "card-strong": "#121f2d",
        success: "#2cc36b",
        danger: "#ef4444",
        warning: "#eab308",
        info: "#38bdf8"
      },
      borderRadius: {
        lg: "8px",
        md: "6px",
        sm: "4px"
      }
    },
  },
  plugins: [animate],
};
