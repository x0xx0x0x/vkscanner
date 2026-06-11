import React, { useState, useEffect } from 'react';
import { getHistory, deleteScan, clearHistory, getScanDetails, searchHistory } from '../utils/api';

export default function HistoryPanel({ onSelectScan, onScanReset, activeScanId, t }) {
  const [historyList, setHistoryList] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const [searchQuery, setSearchQuery] = useState('');

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      if (searchQuery && searchQuery.trim().length >= 2) {
        const data = await searchHistory(searchQuery.trim());
        setHistoryList(data);
      } else {
        const data = await getHistory();
        setHistoryList(data);
      }
    } catch (err) {
      setError(err.message || 'Error loading history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const delayDebounceFn = setTimeout(() => {
      fetchHistory();
    }, 500);
    return () => clearTimeout(delayDebounceFn);
  }, [activeScanId, searchQuery]); // Refresh when a new scan occurs, is selected, or search changes

  const handleSelect = async (scanId) => {
    try {
      const fullScan = await getScanDetails(scanId);
      onSelectScan(fullScan);
    } catch (err) {
      alert(`Error loading scan details: ${err.message}`);
    }
  };

  const handleDelete = async (e, scanId) => {
    e.stopPropagation();
    if (confirm(t?.confirm_delete || 'Are you sure you want to delete this scan record?')) {
      try {
        await deleteScan(scanId);
        setHistoryList(prev => prev.filter(item => item.scan_id !== scanId));
        // Reset current result panel if the deleted scan is active
        onScanReset(scanId);
      } catch (err) {
        alert(`Error: ${err.message}`);
      }
    }
  };

  const handleClearAll = async () => {
    if (confirm(t?.confirm_clear_all || 'Are you sure you want to clear the entire scan history?')) {
      try {
        await clearHistory();
        setHistoryList([]);
        onScanReset(null); // Reset result panel
      } catch (err) {
        alert(`Error: ${err.message}`);
      }
    }
  };

  const formatTime = (isoString) => {
    try {
      const date = new Date(isoString);
      return date.toLocaleString();
    } catch (e) {
      return isoString;
    }
  };

  const getScanIcon = (type) => {
    switch (type) {
      case 'url': return '🔗';
      case 'email': return '📧';
      case 'document': return '📄';
      default: return '🔍';
    }
  };

  return (
    <div className="card" style={{ marginTop: '24px', padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
          ⏱️ {t?.history_title || 'Local Scans History'}
        </h3>
        {historyList.length > 0 && (
          <button 
            className="btn btn--danger" 
            onClick={handleClearAll}
            style={{ padding: '6px 12px', fontSize: '12px' }}
          >
            🗑️ {t?.clear_all_btn || 'Clear All'}
          </button>
        )}
      </div>

      <div style={{ marginBottom: '20px' }}>
        <input 
          type="text" 
          placeholder={t?.search_placeholder || "Search IPs, URLs, hashes, or keywords..."} 
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={{ width: '100%', padding: '10px 16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', background: 'var(--bg-input)', color: 'var(--text-primary)', fontSize: '13px' }}
        />
      </div>

      {loading && historyList.length === 0 && (
        <div style={{ textAlign: 'center', padding: '20px', color: 'var(--text-muted)' }}>
          <span className="spinner" style={{ marginRight: '8px' }} /> {t?.loading_history || 'Loading history...'}
        </div>
      )}

      {error && (
        <div style={{ color: 'var(--risk-high)', padding: '12px', background: 'rgba(239, 68, 68, 0.1)', borderRadius: 'var(--radius-sm)', marginBottom: '16px', fontSize: '13px' }}>
          ❌ {error}
        </div>
      )}

      {!loading && historyList.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)', border: '1px dashed var(--border-color)', borderRadius: 'var(--radius-sm)' }}>
          📭 {t?.no_history || 'No scan history found. Run a scan above to start saving history!'}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '350px', overflowY: 'auto', paddingRight: '4px' }}>
          {historyList.map((item) => {
            const isSelected = activeScanId === item.scan_id;
            const riskColor = item.risk_score > 50 ? 'var(--risk-high)' : item.risk_score > 25 ? 'var(--risk-medium)' : 'var(--risk-low)';
            return (
              <div 
                key={item.scan_id} 
                onClick={() => handleSelect(item.scan_id)}
                style={{
                  padding: '12px 14px',
                  borderRadius: 'var(--radius-md)',
                  border: `1px solid ${isSelected ? 'var(--cyan)' : 'var(--border-primary)'}`,
                  background: isSelected ? 'rgba(6, 182, 212, 0.08)' : 'rgba(255, 255, 255, 0.01)',
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                  position: 'relative'
                }}
                onMouseEnter={(e) => {
                  if (!isSelected) {
                    e.currentTarget.style.background = 'rgba(255, 255, 255, 0.03)';
                    e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.15)';
                  }
                }}
                onMouseLeave={(e) => {
                  if (!isSelected) {
                    e.currentTarget.style.background = 'rgba(255, 255, 255, 0.01)';
                    e.currentTarget.style.borderColor = 'var(--border-primary)';
                  }
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    {formatTime(item.timestamp)}
                  </span>
                  <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }} onClick={e => e.stopPropagation()}>
                    <button 
                      onClick={(e) => handleDelete(e, item.scan_id)}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: 'var(--risk-high)',
                        cursor: 'pointer',
                        fontSize: '12px',
                        padding: '2px',
                        opacity: 0.7
                      }}
                      onMouseEnter={e => e.currentTarget.style.opacity = 1}
                      onMouseLeave={e => e.currentTarget.style.opacity = 0.7}
                      title={t?.delete_btn || 'Delete'}
                    >
                      🗑️
                    </button>
                  </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
                  <div style={{ 
                    fontWeight: 600, 
                    color: 'var(--text-primary)', 
                    fontFamily: 'var(--font-mono)', 
                    fontSize: '12px',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    maxWidth: '240px'
                  }} title={item.target}>
                    {getScanIcon(item.scan_type)} {item.target}
                  </div>
                  <span style={{
                    padding: '2px 6px',
                    background: riskColor + '20',
                    color: riskColor,
                    borderRadius: '4px',
                    fontWeight: 700,
                    border: `1px solid ${riskColor}33`,
                    fontSize: '10px',
                    whiteSpace: 'nowrap'
                  }}>
                    {item.risk_score.toFixed(0)}/100
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
