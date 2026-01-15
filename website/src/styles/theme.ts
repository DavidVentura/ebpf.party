export const darkTheme = {
  bgPrimary: "#1e1f24",
  bgSecondary: "color-mix(in hsl, var(--color-bg-primary), white 5%)",
  codeBg: "#2a2e38",
  codeFg: "#fff",

  textPrimary: "#d4d4d4",
  textHighlight: "#fff",
  textSecondary: "#888888",
  accent: "#61afef",
  alertBg: "#2e1e1e",
  border: "#2a2e38",
  navbarBg: "hsl(224, 14%, 16%)",
  navbarBorder: "hsl(224, 10%, 10%)",
} as const;

export const yellowTheme = {
  bgPrimary: "#fdf6e3",
  bgSecondary: "color-mix(in hsl, var(--color-bg-primary), black 5%)",
  codeBg: "color-mix(in hsl, var(--color-bg-primary), red 25%)",
  codeFg: "black",
  textPrimary: "#575279",
  textHighlight: "#286983",

  textSecondary: "#888888",
  accent: "#d7827e",
  alertBg: "#2e1e1e",
  border: "#2a2e38",
  navbarBg:
    "color-mix(in hsl, var(--color-bg-primary), var(--color-accent) 30%)",
  navbarBorder: "hsl(224, 10%, 10%)",
} as const;

export const roseTheme = {
  bgPrimary: "#faf4ed",
  bgSecondary: "color-mix(in hsl, var(--color-bg-primary), black 5%)",
  codeBg: "color-mix(in hsl, var(--color-bg-primary), red 25%)",
  codeFg: "black",
  textPrimary: "#575279",
  textHighlight: "#286983",

  textSecondary: "#888888",
  accent: "#d7827e",
  alertBg: "#2e1e1e",
  border: "#2a2e38",
  navbarBg:
    "color-mix(in hsl, var(--color-bg-primary), var(--color-accent) 30%)",
  navbarBorder: "hsl(224, 10%, 10%)",
} as const;

export const lightTheme = darkTheme;
