import { useState } from "react";

import { useLogin } from "../../lib/api";

export function LoginPage() {
  const login = useLogin();
  const [form, setForm] = useState({
    email: "admin@endorium.local",
    password: "",
    totp: ""
  });

  return (
    <div className="grid min-h-screen place-items-center px-4 py-8">
      <div className="glow-panel grid max-w-4xl overflow-hidden rounded-[2rem] lg:grid-cols-[1fr_0.9fr]">
        <section className="grid-sheen relative p-8 md:p-12">
          <div className="relative z-10">
            <p className="text-xs uppercase tracking-[0.32em] text-cyan-200/60">Endorium Control Plane</p>
            <h1 className="mt-4 text-4xl font-semibold leading-tight text-slate-50">
              Operate identity, network and trust from one console.
            </h1>
            <p className="mt-5 max-w-lg text-sm leading-7 text-slate-400">
              Sign in with your provisioned admin credentials. If this is a fresh install, generate bootstrap
              secrets with <span className="text-slate-200">nexusctl bootstrap-admin</span> and set them in
              <span className="text-slate-200"> .env.local</span>.
            </p>
          </div>
        </section>

        <section className="p-8 md:p-12">
          <form
            className="relative z-10 grid gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              login.mutate(form);
            }}
          >
            <div>
              <label className="mb-2 block text-xs uppercase tracking-[0.18em] text-slate-500">Email</label>
              <input
                className="w-full rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none"
                onChange={(event) => setForm((current) => ({ ...current, email: event.target.value }))}
                value={form.email}
              />
            </div>
            <div>
              <label className="mb-2 block text-xs uppercase tracking-[0.18em] text-slate-500">Password</label>
              <input
                className="w-full rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none"
                onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
                type="password"
                value={form.password}
              />
            </div>
            <div>
              <label className="mb-2 block text-xs uppercase tracking-[0.18em] text-slate-500">TOTP</label>
              <input
                className="w-full rounded-2xl border border-white/8 bg-black/20 px-4 py-3 outline-none"
                onChange={(event) => setForm((current) => ({ ...current, totp: event.target.value }))}
                value={form.totp}
              />
            </div>
            <button className="accent-gradient rounded-2xl px-4 py-3 font-medium text-slate-950" type="submit">
              Sign in
            </button>
            {login.error ? <p className="text-sm text-rose-200">{login.error.message}</p> : null}
          </form>
        </section>
      </div>
    </div>
  );
}
