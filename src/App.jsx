import { useState } from "react";
import "./App.css";
import { analyzeURL } from "./detector";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);

  const checkURL = () => {
    const res = analyzeURL(url);
    setResult(res);
  };

  return (
    <div className="app">
      <h1>🛡️ PhishGuard</h1>

      <input
        type="text"
        placeholder="Enter URL..."
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />

      <button onClick={checkURL}>Check</button>

      {result && (
        <div className="result">
          <h2>Risk Score: {result.score}%</h2>

          <h3
            className={
              result.status === "Safe"
                ? "safe"
                : result.status === "Suspicious"
                  ? "warn"
                  : "danger blink"
            }
          >
            {result.status}
          </h3>

          {/* 📊 Risk Meter */}
          <div className="meter">
            <div
              className={`meter-fill ${result.status === "Safe"
                  ? "safe-bar"
                  : result.status === "Suspicious"
                    ? "warn-bar"
                    : "danger-bar"
                }`}
              style={{ width: `${result.score}%` }}
            ></div>
          </div>

          {/* 🧠 AI Assistant Style */}
          <div className="chat-box">
            {result.status === "Safe" && (
              <p>✅ This website looks safe. No major threats detected.</p>
            )}

            {result.status === "Suspicious" && (
              <p>⚠️ This site has some suspicious patterns. Be careful.</p>
            )}

            {result.status === "High Risk" && (
              <p className="danger">
                🚨 This website is likely a phishing attack. Avoid entering any data!
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default App;