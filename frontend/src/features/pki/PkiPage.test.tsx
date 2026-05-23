import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { PkiPage } from "./PkiPage";

const createAuthority = {
  mutate: vi.fn(),
  error: null
};

const createCertificate = {
  mutate: vi.fn(),
  error: null
};

const createRevocation = {
  mutate: vi.fn(),
  error: null
};

vi.mock("../../lib/api", () => ({
  usePkiAuthorities: () => ({
    isLoading: false,
    data: [
      {
        name: "root-ca",
        commonName: "Endorium Root CA",
        organization: "Endorium",
        serial: "01",
        certificatePem: "-----BEGIN CERTIFICATE-----",
        privateKeyPem: "-----BEGIN PRIVATE KEY-----",
        createdAt: "2026-01-01T00:00:00Z"
      }
    ]
  }),
  usePkiCertificates: () => ({
    isLoading: false,
    data: []
  }),
  useRevocations: () => ({
    isLoading: false,
    data: []
  }),
  useCreatePkiAuthority: () => createAuthority,
  useCreatePkiCertificate: () => createCertificate,
  useCreateRevocation: () => createRevocation
}));

describe("PkiPage", () => {
  it("offers guided certificate usage profiles in the wizard", () => {
    render(<PkiPage />);

    fireEvent.click(screen.getByRole("button", { name: "Issue Certificate" }));

    expect(screen.getByRole("button", { name: /Web Gateway/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /VPN Gateway/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Service Identity/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Device \/ User Client/i })).toBeInTheDocument();
  });

  it("prefills certificate fields when selecting a profile", () => {
    render(<PkiPage />);

    fireEvent.click(screen.getByRole("button", { name: "Issue Certificate" }));
    fireEvent.click(screen.getByRole("button", { name: /Device \/ User Client/i }));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));

    expect(screen.getByDisplayValue("client.endorium.local")).toBeInTheDocument();
  });
});
