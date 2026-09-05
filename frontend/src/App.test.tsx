import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import App from "./App";

function renderApp(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><App /></MemoryRouter></QueryClientProvider>);
}

describe("Diskard console", () => {
  it("shows the labelled demo history without collapsing execution and outcome", async () => {
    renderApp("/runs");
    expect(await screen.findByRole("heading", { name: "Запуски" })).toBeInTheDocument();
    expect(screen.getByText(/Демонстрационный режим/)).toBeInTheDocument();
    expect(await screen.findByText("Cross-user policy poisoning · investigation")).toBeInTheDocument();
    expect(screen.getAllByText("Завершён").length).toBeGreaterThan(0);
    expect(screen.getAllByText("VULNERABLE").length).toBeGreaterThan(0);
    expect(screen.getAllByText("NO FINDING").length).toBeGreaterThan(0);
  });

  it("renders a run with a trace and memory evidence together", async () => {
    renderApp("/runs/demo-run-240/trace");
    expect(await screen.findByRole("heading", { name: "Трассировка" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Память / evidence" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Cross-user policy poisoning · investigation" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /memory\.finalize/ }));
    expect(screen.getByText("Снимок состояния")).toBeInTheDocument();
  });

  it("keeps recorded playback visibly read-only", async () => {
    renderApp("/runs/demo-run-240/trace");
    await userEvent.click(await screen.findByRole("button", { name: "Recorded playback" }));
    expect((await screen.findAllByText("Recorded playback")).length).toBeGreaterThan(0);
    expect(screen.getByTestId("playback-readonly")).toHaveTextContent("target не вызывается");
    expect(screen.getByRole("button", { name: "Воспроизвести" })).toBeInTheDocument();
  });
});
