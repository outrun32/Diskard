import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import "./styles.css";

console.log(
  "%c" +
    "        __\n" +
    "  .,-;-;-,. /'_\\\n" +
    " _/_/_/_|_\\_\\) /\n" +
    "'-<_><_><_><_>=/\\\n" +
    "  \`/_/====/_/-'\\_\\\n" +
    "   \"\"     \"\"    \"\"\n" +
    "  DISKARD // AI RED TEAM LAB\n" +
    "  Slow and steady wins the memory poisoning race.\n" +
    "  Team: Yakov Saparov, Vladimir Luzin, Alexey Tkachenko",
  "color:#e6b95a;font-family:monospace;font-size:11px;",
);

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false },
  },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
