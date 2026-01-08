import type React from "react";
import styles from "./ControlButton.module.css";

interface ControlButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
  onClick?: () => void;
  pressed?: boolean;
}

export default function ControlButton({
  children,
  onClick,
  pressed = false,
  className,
  ...props
}: ControlButtonProps) {
  return (
    <button
      className={`${styles.controlButton} ${pressed ? styles.pressed : ""} ${className || ""}`}
      onClick={onClick}
      {...props}
    >
      {children}
    </button>
  );
}
