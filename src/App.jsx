import { useState } from "react";
import "./App.css";
import { analyzeURL } from "./detector";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [isScanning, setIsScanning] = useState(false);

  const checkURL = () => {
    if (!url.trim()) return;
    
    // Start scanning animation
    setIsScanning(true);
    setResult(null);

    // Fake delay for the scanning effect to look more accurate
    setTimeout(() => {
      const res = analyzeURL(url);
      setResult(res);
      setIsScanning(false);
    }, 1500);
  };

  const statusClass = result?.status === "Safe" 
    ? "safe" 
    : result?.status === "Warning" 
      ? "warn" 
      : "danger";

  return (
    <div className="app">
      <h1>
        <svg className="shield-icon" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        </svg>
        PhishGuard
      </h1>

      <div className="input-container">
        <input
          type="text"
          placeholder="Enter URL to scan..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && checkURL()}
          disabled={isScanning}
        />

        <button onClick={checkURL} disabled={isScanning || !url.trim()}>
          {isScanning ? (
            "Scanning..."
          ) : (
            <>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="8"></circle>
                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
              </svg>
              Analyze
            </>
          )}
        </button>
      </div>

      {isScanning && (
        <div className="scanner-container">
          <span className="scanner-text">Scanning targets...</span>
          <div className="scanner-line"></div>
        </div>
      )}

      {result && !isScanning && (
        <div className="result">
          <h2>Threat Level: {result.score}%</h2>

          <h3 className={statusClass + (statusClass === "danger" ? " blink" : "")}>
            {result.status}
          </h3>

          {/* 📊 Risk Meter */}
          <div className="meter">
            <div
              className={`meter-fill ${statusClass}-bar`}
              style={{ width: `${result.score}%` }}
            ></div>
          </div>

          {/* 🧠 AI Assistant Style Box */}
          <div className={`chat-box ${statusClass}-box`}>
            {statusClass === "safe" && (
              <>
                <svg className="safe-icon" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                  <polyline points="22 4 12 14.01 9 11.01"></polyline>
                </svg>
                <p>This website looks safe. No malicious patterns detected by our system.</p>
              </>
            )}

            {statusClass === "warn" && (
              <>
                <svg className="warn-icon" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                  <line x1="12" y1="9" x2="12" y2="13"></line>
                  <line x1="12" y1="17" x2="12.01" y2="17"></line>
                </svg>
                <p>Multiple suspicious patterns found. Proceed with extreme caution.</p>
              </>
            )}

            {statusClass === "danger" && (
              <>
                <svg className="danger-icon" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"></circle>
                  <line x1="15" y1="9" x2="9" y2="15"></line>
                  <line x1="9" y1="9" x2="15" y2="15"></line>
                </svg>
                <p className="danger">
                  Phishing threat detected! Close this site immediately and do not enter data.
                </p>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default App;