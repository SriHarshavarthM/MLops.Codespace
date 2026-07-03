import { useEffect, useState } from "react";

function App() {
  const [metrics, setMetrics] = useState<string>("");

  useEffect(() => {
    fetch("/api/v1/metrics")
      .then((response) => response.text())
      .then(setMetrics)
      .catch(console.error);
  }, []);

  return (
    <main style={{ padding: 24 }}>
      <h1>RedMind AI Security Validation</h1>
      <section>
        <h2>Last collected metrics</h2>
        <pre>{metrics || "Loading metrics..."}</pre>
      </section>
    </main>
  );
}

export default App;
