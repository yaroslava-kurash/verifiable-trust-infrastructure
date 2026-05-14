import { useQuery } from "@tanstack/react-query";
import { NavLink, Route, Routes, useLocation } from "react-router-dom";

import { getPlugins } from "@/plugin-api";
import { PluginHost } from "@/components/PluginHost";
import { isSignedIn } from "@/lib/api";
import { Install } from "@/pages/Install";
import { Login } from "@/pages/Login";

export default function App() {
  const plugins = getPlugins();
  const { pathname } = useLocation();

  // `/install` is the unauthenticated install-claim ceremony. It
  // renders standalone (no nav, no plugins) because the operator
  // who hits it doesn't have a session yet.
  if (pathname.startsWith("/install")) {
    return <Install />;
  }

  // Probe the session cookie by hitting an authenticated endpoint.
  // 200 → signed in; 401/403 → show Login. The probe re-runs when
  // the Login page invalidates the query after a successful sign-in.
  const probe = useQuery({
    queryKey: ["session-probe"],
    queryFn: isSignedIn,
    staleTime: 30_000,
    retry: false,
  });

  if (probe.isPending) {
    return <SignInLoading />;
  }
  if (probe.data !== true) {
    return <Login />;
  }

  return (
    <div className="layout">
      <aside className="nav">
        <header>
          <h1>VTC Admin</h1>
        </header>
        <ul>
          {plugins.map((p) => (
            <li key={p.id}>
              <NavLink to={p.path}>
                <span className="nav-icon" aria-hidden="true">
                  {p.icon ?? p.label.charAt(0).toUpperCase()}
                </span>
                <span className="nav-label">{p.label}</span>
              </NavLink>
            </li>
          ))}
        </ul>
      </aside>
      <main className="content">
        <Routes>
          {plugins.map((p) => (
            <Route
              key={p.id}
              path={`${p.path}/*`}
              element={<PluginHost plugin={p} />}
            />
          ))}
          {/* Default route: first plugin (Dashboard). */}
          {plugins[0] && (
            <Route path="/" element={<PluginHost plugin={plugins[0]} />} />
          )}
          {/* Fallback for unknown URLs under /admin/ */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
    </div>
  );
}

function SignInLoading() {
  return (
    <section className="page login-page">
      <div className="login-card">
        <h2>VTC Admin</h2>
        <p className="lead">Checking session…</p>
      </div>
    </section>
  );
}

function NotFound() {
  return (
    <section className="page">
      <h2>Not found</h2>
      <p>
        The URL didn't match a registered plugin. The nav on the left
        shows what's available.
      </p>
    </section>
  );
}
