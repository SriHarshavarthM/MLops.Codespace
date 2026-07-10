import { ChangeEvent, useEffect, useMemo, useState } from "react";

type ModelOption = {
  id: string;
  display_name: string;
  api_model: string;
  endpoint?: string;
};

type ScenarioOption = {
  id: string;
  description: string;
  severity: string;
  examples: string[];
};

type ValidationResult = {
  run_id?: string;
  metrics?: Record<string, number>;
  drift?: { alert?: boolean; details?: Record<string, unknown> };
  alert_payload?: string | null;
  results_count?: number;
  model_name?: string;
  dataset_path?: string;
};

type AppStatus = {
  status?: string;
  dataset_exists?: boolean;
  dataset_path?: string;
  models_count?: number;
  scenarios_count?: number;
  metrics_endpoint?: string;
};

function App() {
  const [metricsText, setMetricsText] = useState("");
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [models, setModels] = useState<ModelOption[]>([]);
  const [scenarios, setScenarios] = useState<ScenarioOption[]>([]);
  const [selectedModel, setSelectedModel] = useState("");
  const [selectedScenario, setSelectedScenario] = useState("");
  const [result, setResult] = useState<ValidationResult | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    Promise.all([
      fetch("/api/v1/metrics").then((response) => response.text()),
      fetch("/api/v1/status").then((response) => response.json()),
      fetch("/api/v1/models").then((response) => response.json()),
      fetch("/api/v1/scenarios").then((response) => response.json()),
    ])
      .then(([metrics, statusPayload, modelsPayload, scenariosPayload]) => {
        setMetricsText(metrics);
        setStatus(statusPayload);
        setModels(modelsPayload.models || []);
        setScenarios(scenariosPayload.scenarios || []);
        if ((modelsPayload.models || []).length > 0) {
          setSelectedModel(modelsPayload.models[0].id);
        }
        if ((scenariosPayload.scenarios || []).length > 0) {
          setSelectedScenario(scenariosPayload.scenarios[0].id);
        }
      })
      .catch((err) => {
        console.error(err);
        setError("Unable to load dashboard data from the backend.");
      });
  }, []);

  const selectedScenarioDetails = useMemo(
    () => scenarios.find((scenario: ScenarioOption) => scenario.id === selectedScenario),
    [scenarios, selectedScenario]
  );

  const runValidation = async () => {
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch("/api/v1/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model_name: selectedModel,
          dataset_path: "data/raw/attack_vectors.csv",
          temperature: 0.2,
          baseline_score: 90,
          threshold_drop: 10,
        }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || "Validation request failed.");
      }
      setResult(payload);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Validation request failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main style={{ padding: 24, fontFamily: "Inter, Arial, sans-serif", background: "#f4f7fb", minHeight: "100vh" }}>
      <h1 style={{ marginBottom: 8 }}>RedMind AI Security Validation</h1>
      <p style={{ marginTop: 0, color: "#475569" }}>
        Monitor security drift, trigger adversarial validation runs, and inspect the current model posture from one place.
      </p>

      <section style={{ display: "grid", gap: 16, gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", marginBottom: 24 }}>
        <article style={{ background: "#fff", borderRadius: 12, padding: 16, boxShadow: "0 8px 24px rgba(15, 23, 42, 0.06)" }}>
          <h2 style={{ marginTop: 0 }}>Backend status</h2>
          <p><strong>Status:</strong> {status?.status ?? "loading"}</p>
          <p><strong>Dataset:</strong> {status?.dataset_exists ? "ready" : "missing"}</p>
          <p><strong>Models configured:</strong> {status?.models_count ?? 0}</p>
        </article>
        <article style={{ background: "#fff", borderRadius: 12, padding: 16, boxShadow: "0 8px 24px rgba(15, 23, 42, 0.06)" }}>
          <h2 style={{ marginTop: 0 }}>Run validation</h2>
          <label style={{ display: "block", marginBottom: 8 }}>
            <span style={{ display: "block", marginBottom: 4 }}>Model</span>
            <select value={selectedModel} onChange={(event: ChangeEvent<HTMLSelectElement>) => setSelectedModel(event.target.value)} style={{ width: "100%", padding: 8 }}>
              {models.map((model: ModelOption) => (
                <option key={model.id} value={model.id}>
                  {model.display_name}
                </option>
              ))}
            </select>
          </label>
          <label style={{ display: "block", marginBottom: 12 }}>
            <span style={{ display: "block", marginBottom: 4 }}>Scenario</span>
            <select value={selectedScenario} onChange={(event: ChangeEvent<HTMLSelectElement>) => setSelectedScenario(event.target.value)} style={{ width: "100%", padding: 8 }}>
              {scenarios.map((scenario: ScenarioOption) => (
                <option key={scenario.id} value={scenario.id}>
                  {scenario.id}
                </option>
              ))}
            </select>
          </label>
          <button onClick={runValidation} disabled={loading || !selectedModel} style={{ padding: "10px 14px", cursor: "pointer" }}>
            {loading ? "Running..." : "Run validation"}
          </button>
          {error ? <p style={{ color: "#b91c1c" }}>{error}</p> : null}
        </article>
      </section>

      <section style={{ display: "grid", gap: 16, gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", marginBottom: 24 }}>
        <article style={{ background: "#fff", borderRadius: 12, padding: 16, boxShadow: "0 8px 24px rgba(15, 23, 42, 0.06)" }}>
          <h2 style={{ marginTop: 0 }}>Scenario focus</h2>
          {selectedScenarioDetails ? (
            <>
              <p><strong>Severity:</strong> {selectedScenarioDetails.severity}</p>
              <p>{selectedScenarioDetails.description}</p>
              <ul>
                {selectedScenarioDetails.examples.map((example) => (
                  <li key={example}>{example}</li>
                ))}
              </ul>
            </>
          ) : (
            <p>No scenarios available yet.</p>
          )}
        </article>
        <article style={{ background: "#fff", borderRadius: 12, padding: 16, boxShadow: "0 8px 24px rgba(15, 23, 42, 0.06)" }}>
          <h2 style={{ marginTop: 0 }}>Latest validation result</h2>
          {result ? (
            <>
              <p><strong>Model:</strong> {result.model_name}</p>
              <p><strong>Run ID:</strong> {result.run_id ?? "n/a"}</p>
              <p><strong>Results evaluated:</strong> {result.results_count ?? 0}</p>
              <p><strong>Security trust score:</strong> {result.metrics?.security_trust_score ?? "n/a"}</p>
              <p><strong>Drift alert:</strong> {result.drift?.alert ? "Yes" : "No"}</p>
            </>
          ) : (
            <p>No validation run executed yet.</p>
          )}
        </article>
      </section>

      <section style={{ background: "#fff", borderRadius: 12, padding: 16, boxShadow: "0 8px 24px rgba(15, 23, 42, 0.06)" }}>
        <h2 style={{ marginTop: 0 }}>Prometheus metrics snapshot</h2>
        <pre style={{ whiteSpace: "pre-wrap", background: "#0f172a", color: "#f8fafc", padding: 12, borderRadius: 8, overflowX: "auto" }}>
          {metricsText || "Loading metrics..."}
        </pre>
      </section>
    </main>
  );
}

export default App;
