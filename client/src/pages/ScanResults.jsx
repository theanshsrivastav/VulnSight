import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../utils/api';

export default function ScanResults() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    fetchScanDetails();
  }, [id]);

  useEffect(() => {
    if (scan && (scan.status === 'pending' || scan.status === 'running')) {
      const interval = setInterval(() => {
        fetchScanDetails(true);
      }, 3000);
      return () => clearInterval(interval);
    }
  }, [scan]);

  const fetchScanDetails = async (isPoll = false) => {
    if (!isPoll) setLoading(true);
    try {
      const response = await api.get(`/scans/${id}`);
      setScan(response.data);
    } catch (err) {
      console.error('Failed to fetch scan details', err);
    } finally {
      if (!isPoll) setLoading(false);
    }
  };

  const handleDownloadPDF = async () => {
    setDownloading(true);
    try {
      const response = await api.get(`/reports/scans/${id}/pdf`, {
        responseType: 'blob',
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `VulnSight_Report_Scan_${id}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to download PDF report', err);
    } finally {
      setDownloading(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': 'bg-red-100 text-red-800 border-red-200',
      'High': 'bg-orange-100 text-orange-800 border-orange-200',
      'Medium': 'bg-yellow-100 text-yellow-800 border-yellow-200',
      'Low': 'bg-green-100 text-green-800 border-green-200'
    };
    return colors[severity] || 'bg-gray-100 text-gray-800 border-gray-200';
  };

  const getSeverityBadge = (severity) => {
    const colors = {
      'Critical': 'bg-red-600 text-white',
      'High': 'bg-orange-600 text-white',
      'Medium': 'bg-yellow-600 text-white',
      'Low': 'bg-green-600 text-white'
    };
    return colors[severity] || 'bg-gray-600 text-white';
  };

  const getStatusColor = (status) => {
    const colors = {
      'completed': 'bg-green-100 text-green-800 border-green-200',
      'running': 'bg-blue-100 text-blue-800 border-blue-200',
      'failed': 'bg-red-100 text-red-800 border-red-200',
      'pending': 'bg-yellow-100 text-yellow-800 border-yellow-200'
    };
    return colors[status] || 'bg-gray-100 text-gray-800 border-gray-200';
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center min-h-screen">
        <div className="text-xl">Loading scan results...</div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="flex justify-center items-center min-h-screen">
        <div className="text-xl">Scan not found</div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="flex justify-between items-center mb-6">
        <button
          onClick={() => navigate('/dashboard')}
          className="text-indigo-600 hover:text-indigo-800 font-medium"
        >
          ← Back to Dashboard
        </button>
        {scan.status === 'completed' && (
          <button
            onClick={handleDownloadPDF}
            disabled={downloading}
            className="bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-md shadow transition duration-150 disabled:bg-indigo-400 flex items-center"
          >
            {downloading ? (
              <>
                <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Generating PDF...
              </>
            ) : (
              '📥 Download PDF Report'
            )}
          </button>
        )}
      </div>

      <div className="bg-white shadow rounded-lg p-6 mb-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-4 font-sans">Scan Details</h1>
        
        {(scan.status === 'pending' || scan.status === 'running') && (
          <div className="mb-6 p-4 bg-blue-50 border border-blue-200 text-blue-800 rounded-lg flex items-center space-x-3">
            <svg className="animate-spin h-5 w-5 text-blue-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>Scan is currently <b>{scan.status}</b>. The page will automatically refresh with live vulnerability findings...</span>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <p className="text-sm text-gray-500">Target URL</p>
            <p className="text-lg font-medium break-all">{scan.target_url}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Scan Type</p>
            <p className="text-lg font-medium capitalize">{scan.scan_type.replace('_', ' ')}</p>
          </div>
          <div>
            <p className="text-sm text-gray-500">Status</p>
            <span className={`inline-block px-3 py-1 rounded-full text-sm font-medium mt-1 ${getStatusColor(scan.status)}`}>
              {scan.status}
            </span>
          </div>
        </div>
        <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-gray-100 pt-4">
          <div>
            <p className="text-sm text-gray-500">Started At</p>
            <p className="text-lg">{new Date(scan.started_at).toLocaleString()}</p>
          </div>
          {scan.completed_at && (
            <div>
              <p className="text-sm text-gray-500">Completed At</p>
              <p className="text-lg">{new Date(scan.completed_at).toLocaleString()}</p>
            </div>
          )}
        </div>
      </div>

      <div className="bg-white shadow rounded-lg p-6">
        <div className="flex justify-between items-center mb-6 border-b border-gray-100 pb-4">
          <h2 className="text-2xl font-semibold">
            Vulnerabilities Found ({scan.vulnerabilities?.length || 0})
          </h2>
        </div>

        {!scan.vulnerabilities || scan.vulnerabilities.length === 0 ? (
          scan.status === 'completed' ? (
            <div className="text-center py-12">
              <div className="text-6xl mb-4 text-green-500">✓</div>
              <h3 className="text-xl font-medium text-green-600 mb-2">No vulnerabilities detected!</h3>
              <p className="text-gray-500">Your target appears to be secure from the tested vulnerability vectors.</p>
            </div>
          ) : (
            <div className="text-center py-12 text-gray-500">
              Waiting for scanning engine to populate vulnerability reports...
            </div>
          )
        ) : (
          <div className="space-y-6">
            {scan.vulnerabilities.map((vuln) => (
              <div key={vuln.id} className={`border-l-4 p-5 rounded-r-lg shadow-sm border ${getSeverityColor(vuln.severity)}`}>
                <div className="flex justify-between items-start mb-2">
                  <h3 className="text-xl font-semibold text-gray-900">{vuln.vulnerability_type}</h3>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${getSeverityBadge(vuln.severity)}`}>
                    {vuln.severity}
                  </span>
                </div>
                
                <p className="text-gray-700 mb-4">{vuln.description}</p>
                
                <div className="space-y-3 bg-white p-4 rounded border border-gray-200 mt-2">
                  <div>
                    <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Affected URL:</p>
                    <p className="text-sm text-gray-800 break-all font-mono">{vuln.affected_url}</p>
                  </div>
                  
                  {vuln.evidence && (
                    <div>
                      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Evidence:</p>
                      <pre className="text-xs bg-gray-50 p-2 rounded mt-1 overflow-x-auto border border-gray-100 font-mono text-gray-800">
                        {JSON.stringify(vuln.evidence, null, 2)}
                      </pre>
                    </div>
                  )}
                  
                  {vuln.remediation && (
                    <div className="bg-blue-50 border border-blue-100 p-3 rounded">
                      <p className="text-xs font-semibold text-blue-700 uppercase tracking-wider">Remediation Guide:</p>
                      <p className="text-sm text-blue-900 mt-1">{vuln.remediation}</p>
                    </div>
                  )}

                  {/* AI Remediation suggestions mapping */}
                  {vuln.ai_remediation && (
                    <div className="mt-4 bg-purple-50 border border-purple-200 p-4 rounded-md space-y-3 shadow-inner">
                      <p className="text-sm font-bold text-purple-900 flex items-center border-b border-purple-200 pb-1">
                        ✨ AI Remediation Insight (Advanced Security Guide)
                      </p>
                      <div>
                        <p className="text-xs font-bold text-purple-800 uppercase tracking-wider">Analysis Explanation:</p>
                        <p className="text-sm text-purple-900 mt-0.5">{vuln.ai_remediation.explanation}</p>
                      </div>
                      <div>
                        <p className="text-xs font-bold text-purple-800 uppercase tracking-wider">Threat & Impact:</p>
                        <p className="text-sm text-purple-900 mt-0.5">{vuln.ai_remediation.impact}</p>
                      </div>
                      <div>
                        <p className="text-xs font-bold text-purple-800 uppercase tracking-wider">Fix recommendation:</p>
                        <p className="text-sm text-purple-900 mt-0.5">{vuln.ai_remediation.fix_recommendation}</p>
                      </div>
                      <div>
                        <p className="text-xs font-bold text-purple-800 uppercase tracking-wider">Secure Coding Example:</p>
                        <pre className="text-xs bg-purple-100 text-purple-950 p-2 rounded mt-1 overflow-x-auto font-mono">
                          {vuln.ai_remediation.secure_coding}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
