import { act, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "../app/App";
import { LoginPage } from "../features/settings/LoginPage";

class MockEventSource {
  static instances: MockEventSource[] = [];

  private listeners = new Map<string, Set<EventListener>>();

  readonly close = vi.fn();
  readonly url: string;

  constructor(url: string) {
    this.url = url;
    MockEventSource.instances.push(this);
  }

  addEventListener(type: string, listener: EventListenerOrEventListenerObject) {
    const callback =
      typeof listener === "function" ? listener : (event: Event) => listener.handleEvent(event);
    const listeners = this.listeners.get(type) ?? new Set<EventListener>();
    listeners.add(callback);
    this.listeners.set(type, listeners);
  }

  removeEventListener(type: string, listener: EventListenerOrEventListenerObject) {
    const callback =
      typeof listener === "function" ? listener : (event: Event) => listener.handleEvent(event);
    this.listeners.get(type)?.delete(callback);
  }

  emit(type: string) {
    this.listeners.get(type)?.forEach((listener) => listener(new Event(type)));
  }

  static reset() {
    MockEventSource.instances = [];
  }
}

describe("frontend auth shell", () => {
  beforeEach(() => {
    MockEventSource.reset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("renders the bootstrap copy", () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <LoginPage />
      </QueryClientProvider>
    );
    expect(screen.getByText(/Une console claire pour les services essentiels/i)).toBeInTheDocument();
  });

  it("refreshes live queries when the platform stream emits a state change", async () => {
    let dashboardRequests = 0;

    vi.stubGlobal("EventSource", MockEventSource as unknown as typeof EventSource);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

        if (url.endsWith("/api/v1/auth/me")) {
          return new Response(
            JSON.stringify({
              email: "admin@endorium.local",
              roles: ["superadmin"]
            }),
            {
              status: 200,
              headers: { "Content-Type": "application/json" }
            }
          );
        }

        if (url.endsWith("/api/v1/dashboard")) {
          dashboardRequests += 1;
          return new Response(
            JSON.stringify({
              services: [],
              directoryObjects: 5,
              dnsRecords: 4,
              dhcpLeases: 2,
              pendingJobs: 1,
              pkiRevocations: 1,
              repoPackages: 2,
              jobs: [],
              audit: []
            }),
            {
              status: 200,
              headers: { "Content-Type": "application/json" }
            }
          );
        }

        return new Response(JSON.stringify([]), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      })
    );

    render(<App />);

    await screen.findByText(/Connecté en tant que/i);
    await waitFor(() => expect(MockEventSource.instances).toHaveLength(1));
    expect(MockEventSource.instances[0]?.url).toBe("/api/v1/dashboard/stream");
    await waitFor(() => expect(dashboardRequests).toBe(1));

    await act(async () => {
      MockEventSource.instances[0]?.emit("state-changed");
    });

    await waitFor(() => expect(dashboardRequests).toBe(2));
  });
});
