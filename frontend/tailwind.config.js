/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#07111f",
        panel: "#0d1a2b",
        line: "#1d3045",
        signal: "#4de0b2",
      },
    },
  },
  plugins: [],
};
