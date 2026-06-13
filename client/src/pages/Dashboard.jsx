import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../utils/api';

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState('full');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const response = await api.get('/scans');
      setScans(response.data);
    } catch (err) {
      console.error('Failed to fetch scans', err);
    }
  };

  const handleScan = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await api.post('/scans/', {
        target_url: targetUrl,
        scan_type: scanType
      });
      setTargetUrl('');
      fetchScans();
    } catch (err) {
      setError(err.response?.data?.detail || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const deleteScan = async (id) => {
    try {
      await api.delete(`/scans/${id}`);
      fetchScans();
    } catch (err) {
      console.error('Failed to delete scan', err);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': 'bg-red-100 text-red-800',
      'High': 'bg-orange-100 text-orange-800',
      'Medium': 'bg-yellow-100 text-yellow-800',
      'Low': 'bg-green-100 text-green-800'
    };
    return colors[severity] || 'bg-gray-100 text-gray-800';
  };

  const getStatusColor = (status) => {
    const colors = {
      'completed': 'bg-green-100 text-green-800',
      'running': 'bg-blue-100 text-blue-800',
      'failed': 'bg-red-100 text-red-800',
      'pending': 'bg-yellow-100 text-yellow-800'
    };
    return colors[status] || 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <h1 className="text-3xl font-bold text-gray-900 mb-8">Security Scan Dashboard</h1>

      <div className="bg-white shadow rounded-lg p-6 mb-8">
        <h2 className="text-xl font-semibold mb-4">Start New Scan</h2>
        <form onSubmit={handleScan} className="space-y-4">
          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
              {error}
            </div>
          )}
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Target URL
            </label>
            <input
              type="url"
              required
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Scan Type
            </label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
            >
              <option value="comprehensive">🔒 Comprehensive Scan (All Tools)</option>
              <option value="full">Full Scan (XSS + SQL Injection)</option>
              <option value="xss">XSS Only</option>
              <option value="sql_injection">SQL Injection Only</option>
              <option value="nmap">Nmap (Port & Network Scan)</option>
              <option value="nikto">Nikto (Web Server Scan)</option>
              <option value="zap">OWASP ZAP (Automated Security)</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-indigo-600 text-white py-2 px-4 rounded-md hover:bg-indigo-700 disabled:bg-indigo-400"
          >
            {loading ? 'Scanning...' : 'Start Scan'}
          </button>
        </form>
      </div>

      <div className="bg-white shadow rounded-lg p-6">
        <h2 className="text-xl font-semibold mb-4">Scan History</h2>
        
        {scans.length === 0 ? (
          <p className="text-gray-500 text-center py-8">No scans yet. Start your first security scan above!</p>
        ) : (
          <div className="space-y-4">
            {scans.map((scan) => (
              <div key={scan.id} className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3">
                      <h3 className="text-lg font-medium text-gray-900">{scan.target_url}</h3>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(scan.status)}`}>
                        {scan.status}
                      </span>
                    </div>
                    <p className="text-sm text-gray-500 mt-1">
                      Type: {scan.scan_type} | Started: {new Date(scan.started_at).toLocaleString()}
                    </p>
                  </div>
                  <div className="flex space-x-2">
                    <Link
                      to={`/scan/${scan.id}`}
                      className="bg-indigo-100 text-indigo-700 px-3 py-1 rounded hover:bg-indigo-200"
                    >
                      View Details
                    </Link>
                    <button
                      onClick={() => deleteScan(scan.id)}
                      className="bg-red-100 text-red-700 px-3 py-1 rounded hover:bg-red-200"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
