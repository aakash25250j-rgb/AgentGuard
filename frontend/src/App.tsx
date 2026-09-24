import "./App.css";

function App() {
  return (
    <div className="app">
      <header className="topbar">
        <div>
          <h1>🛡️ AgentGuard</h1>
          <p>AI Agent Security Operations Center</p>
        </div>

        <div className="status">
          <span className="dot"></span>
          System Online
        </div>
      </header>

      <main>
        <section className="stats">
          <div className="card">
            <h3>Active Agents</h3>
            <strong>12</strong>
            <span>Currently monitored</span>
          </div>

          <div className="card danger">
            <h3>Critical Incidents</h3>
            <strong>2</strong>
            <span>Immediate attention</span>
          </div>

          <div className="card warning">
            <h3>High Risk</h3>
            <strong>3</strong>
            <span>Under review</span>
          </div>

          <div className="card">
            <h3>SOC Capacity</h3>
            <strong>5 / 5</strong>
            <span>Investigation slots</span>
          </div>
        </section>

        <section className="panel">
          <h2>Risk Overview</h2>

          <div className="risk-grid">
            <div>
              <span>Critical</span>
              <strong className="critical">2</strong>
            </div>

            <div>
              <span>High</span>
              <strong className="high">3</strong>
            </div>

            <div>
              <span>Medium</span>
              <strong className="medium">2</strong>
            </div>

            <div>
              <span>Low</span>
              <strong className="low">5</strong>
            </div>
          </div>
        </section>

        <section className="panel">
          <h2>Recent Security Incidents</h2>

          <table>
            <thead>
              <tr>
                <th>Agent</th>
                <th>Risk Score</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>

            <tbody>
              <tr>
                <td>DevAgent-07</td>
                <td>94</td>
                <td><span className="badge critical-bg">CRITICAL</span></td>
                <td>Active</td>
                <td>ISOLATE</td>
              </tr>

              <tr>
                <td>FinanceAgent-02</td>
                <td>87</td>
                <td><span className="badge high-bg">HIGH</span></td>
                <td>Review</td>
                <td>REVIEW</td>
              </tr>

              <tr>
                <td>HR-Agent-04</td>
                <td>81</td>
                <td><span className="badge high-bg">HIGH</span></td>
                <td>Review</td>
                <td>REVIEW</td>
              </tr>

              <tr>
                <td>DevAgent-03</td>
                <td>76</td>
                <td><span className="badge high-bg">HIGH</span></td>
                <td>Active</td>
                <td>REVIEW</td>
              </tr>
            </tbody>
          </table>
        </section>
      </main>
    </div>
  );
}

export default App;