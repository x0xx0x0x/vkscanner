/**
 * API client for VK Scanner backend.
 */

const API_BASE = '/api';

async function handleResponse(response) {
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(error.detail || `HTTP ${response.status}`);
  }
  return response.json();
}

function getThirdPartyHeaders() {
  const headers = {};
  const runThirdParty = localStorage.getItem('vk_run_third_party') === 'true';
  headers['X-Run-Third-Party'] = runThirdParty ? 'true' : 'false';
  
  const vtKey = localStorage.getItem('vk_virustotal_key');
  if (vtKey) headers['X-VirusTotal-Key'] = vtKey;
  
  const urlscanKey = localStorage.getItem('vk_urlscan_key');
  if (urlscanKey) headers['X-URLScan-Key'] = urlscanKey;
  
  const abuseKey = localStorage.getItem('vk_abuseipdb_key');
  if (abuseKey) headers['X-AbuseIPDB-Key'] = abuseKey;
  
  return headers;
}

export async function scanUrl(url, followRedirects = true) {
  const extraHeaders = getThirdPartyHeaders();
  const response = await fetch(`${API_BASE}/scan/url`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      ...extraHeaders
    },
    body: JSON.stringify({ url, follow_redirects: followRedirects }),
  });
  return handleResponse(response);
}

export async function scanEmail(data) {
  const extraHeaders = getThirdPartyHeaders();
  const response = await fetch(`${API_BASE}/scan/email`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      ...extraHeaders
    },
    body: JSON.stringify(data),
  });
  return handleResponse(response);
}

export async function scanEmailFile(file) {
  const formData = new FormData();
  formData.append('file', file);
  const extraHeaders = getThirdPartyHeaders();

  const response = await fetch(`${API_BASE}/scan/email-file`, {
    method: 'POST',
    headers: {
      ...extraHeaders
    },
    body: formData,
  });
  return handleResponse(response);
}

export async function scanDocument(file, password = null, customPasswords = null, wordlistFile = null) {
  const formData = new FormData();
  formData.append('file', file);
  if (password) formData.append('password', password);
  if (customPasswords) formData.append('custom_passwords', customPasswords);
  if (wordlistFile) formData.append('wordlist_file', wordlistFile);

  const extraHeaders = getThirdPartyHeaders();

  const response = await fetch(`${API_BASE}/scan/document`, {
    method: 'POST',
    headers: {
      ...extraHeaders
    },
    body: formData,
  });
  return handleResponse(response);
}

export async function healthCheck() {
  const response = await fetch(`${API_BASE}/health`);
  return handleResponse(response);
}

export async function getHistory() {
  const response = await fetch(`${API_BASE}/scan/history`);
  const data = await handleResponse(response);
  return data.history || data; // handle object wrapper if any
}

export async function searchHistory(query) {
  const response = await fetch(`${API_BASE}/scan/search?q=${encodeURIComponent(query)}`);
  const data = await handleResponse(response);
  return data.results || [];
}

export async function getScanDetails(scanId) {
  const response = await fetch(`${API_BASE}/scan/history/${scanId}`);
  return handleResponse(response);
}

export async function deleteScan(scanId) {
  const response = await fetch(`${API_BASE}/scan/history/${scanId}`, {
    method: 'DELETE',
  });
  return handleResponse(response);
}

export async function clearHistory() {
  const response = await fetch(`${API_BASE}/scan/history`, {
    method: 'DELETE',
  });
  return handleResponse(response);
}
