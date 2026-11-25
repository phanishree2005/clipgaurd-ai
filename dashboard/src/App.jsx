import React, { useState, useEffect, useRef } from 'react';
import { Shield, ShieldAlert, Activity, Cpu, Server, Database, AlertTriangle } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws';

function App() {
  const [events, setEvents] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [stats, setStats] = useState({
    totalEvents: 0,
    highRisk: 0,
    anomalies: 0,
    activeProcesses: new Set()
  });
  const [chartData, setChartData] = useState([]);

  useEffect(() => {
    let ws;
    let reconnectTimer;

    const connect = () => {
      ws = new WebSocket(WS_URL);

      ws.onopen = () => {
        setIsConnected(true);
      };

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        setEvents(prev => [data, ...prev].slice(0, 50)); // Keep last 50 events
        
        setStats(prev => {
          const newProcesses = new Set(prev.activeProcesses);
          newProcesses.add(data.process_name);
          
          return {
            totalEvents: prev.totalEvents + 1,
            highRisk: prev.highRisk + (data.overall_risk > 50 ? 1 : 0),
            anomalies: prev.anomalies + (data.findings.behavior?.is_anomaly ? 1 : 0),
            activeProcesses: newProcesses
          };
        });

        // Update chart data
        setChartData(prev => {
          const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second:'2-digit' });
          const newData = [...prev, { time: now, risk: data.overall_risk }];
          return newData.slice(-20); // Keep last 20 points
        });
      };

      ws.onclose = () => {
        setIsConnected(false);
        reconnectTimer = setTimeout(connect, 3000);
      };
      
      ws.onerror = () => {
        ws.close();
      };
    };

    connect();

    return () => {
      if (ws) ws.close();
      clearTimeout(reconnectTimer);
    };
  }, []);

  return (
    <div className="dashboard-container">
      <header className="header">
        <div>
          <h1>ClipGuard</h1>
          <p style={{ color: 'var(--text-secondary)', margin: '8px 0 0 0' }}>Zero-Trust DLP & Insider Threat Intelligence</p>
        </div>
        <div className={`status-badge ${!isConnected ? 'disconnected' : ''}`}>
          <div className="status-dot"></div>
          {isConnected ? 'System Active & Monitoring' : 'Disconnected - Reconnecting...'}
        </div>
      </header>

      <div className="grid" style={{ marginBottom: '24px' }}>
        <div className="col-4 glass-panel stat-card">
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span className="stat-title">Intercepted Events</span>
            <Activity size={20} color="var(--accent-blue)" />
          </div>
          <span className="stat-value">{stats.totalEvents}</span>
        </div>
        
        <div className="col-4 glass-panel stat-card">
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span className="stat-title">Critical Threats (Risk > 50)</span>
            <ShieldAlert size={20} color="var(--accent-red)" />
          </div>
          <span className={`stat-value ${stats.highRisk > 0 ? 'high-risk' : ''}`}>
            {stats.highRisk}
          </span>
        </div>
        
        <div className="col-4 glass-panel stat-card">
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span className="stat-title">Behavioral Anomalies</span>
            <Cpu size={20} color="var(--accent-orange)" />
          </div>
          <span className={`stat-value ${stats.anomalies > 0 ? 'medium-risk' : 'low-risk'}`}>
            {stats.anomalies}
          </span>
        </div>
      </div>

      <div className="grid">
        <div className="col-8 glass-panel">
          <h2 style={{ margin: '0 0 24px 0', fontSize: '1.25rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Activity size={20} /> Live Threat Telemetry
          </h2>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent-red)" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="var(--accent-red)" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                <XAxis dataKey="time" stroke="var(--text-secondary)" fontSize={12} />
                <YAxis stroke="var(--text-secondary)" fontSize={12} domain={[0, 100]} />
                <Tooltip 
                  contentStyle={{ backgroundColor: 'var(--bg-color)', border: '1px solid var(--glass-border)', borderRadius: '8px' }}
                />
                <Area type="monotone" dataKey="risk" stroke="var(--accent-red)" fillOpacity={1} fill="url(#colorRisk)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="col-4 glass-panel">
          <h2 style={{ margin: '0 0 24px 0', fontSize: '1.25rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Server size={20} /> Interception Feed
          </h2>
          
          <div className="feed-container">
            {events.length === 0 ? (
              <div className="empty-state">
                <Shield size={48} style={{ marginBottom: '16px', opacity: 0.5 }} />
                <p>No clipboard events intercepted yet.</p>
                <p style={{ fontSize: '0.8rem' }}>Waiting for agent telemetry...</p>
              </div>
            ) : (
              events.map((evt, idx) => {
                const riskClass = evt.overall_risk > 70 ? 'risk-high' : evt.overall_risk > 30 ? 'risk-medium' : 'risk-low';
                
                return (
                  <div key={idx} className={`event-card ${riskClass}`}>
                    <div className="event-header">
                      <div className="process-info">
                        <Database size={16} />
                        {evt.process_name}
                        <span className="pid-badge">PID: {evt.process_id}</span>
                      </div>
                      <span className="timestamp">
                        {new Date(evt.timestamp * 1000).toLocaleTimeString()}
                      </span>
                    </div>
                    
                    <div className="redacted-text">
                      {evt.redacted_text.length > 100 ? evt.redacted_text.substring(0, 100) + '...' : evt.redacted_text}
                    </div>
                    
                    <div className="findings-list">
                      {evt.findings.nlp_regex.map((f, i) => (
                        <span key={`nlp-${i}`} className="finding-tag nlp">
                          <AlertTriangle size={12} /> {f.type} (NLP/Regex)
                        </span>
                      ))}
                      {evt.findings.yara.map((f, i) => (
                        <span key={`yara-${i}`} className="finding-tag yara">
                          <ShieldAlert size={12} /> YARA: {f.rule}
                        </span>
                      ))}
                      {evt.findings.threat_intel.map((f, i) => (
                        <span key={`intel-${i}`} className="finding-tag yara">
                          <AlertTriangle size={12} /> Intel: {f.type}
                        </span>
                      ))}
                      {evt.findings.behavior.is_anomaly && (
                        <span className="finding-tag behavior">
                          <Cpu size={12} /> {evt.findings.behavior.reason}
                        </span>
                      )}
                    </div>
                    
                    <div style={{ marginTop: '12px', fontSize: '0.85rem', color: 'var(--text-secondary)', display: 'flex', justifyContent: 'space-between' }}>
                      <span>Risk Score: <strong style={{ color: 'white' }}>{evt.overall_risk.toFixed(0)}/100</strong></span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
