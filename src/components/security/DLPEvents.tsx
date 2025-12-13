import { Shield, AlertTriangle, Ban, Eye, Search, Filter, Download, Users, Activity, Database, AlertCircle } from 'lucide-react';
import { DashboardLayout } from '../layouts/DashboardLayout';
import { useState } from 'react';

const sidebarItems = [
  { icon: <Shield className="w-5 h-5" />, label: 'Dashboard', path: '/admin/dashboard' },
  { icon: <Users className="w-5 h-5" />, label: 'User Management', path: '/admin/users' },
  { icon: <Activity className="w-5 h-5" />, label: 'Audit Logs', path: '/admin/audit-logs' },
  { icon: <Database className="w-5 h-5" />, label: 'Backup & Recovery', path: '/admin/backup' },
  { icon: <AlertCircle className="w-5 h-5" />, label: 'Data Retention', path: '/admin/data-retention' },
];

export function DLPEvents() {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');

  const events: DLPEvent[] = [
    { 
      id: 'DLP001', 
      timestamp: '2024-12-12 10:45:23', 
      user: 'Dr. Chen Wei Ming', 
      role: 'doctor', 
      action: 'Copy NRIC', 
      dataType: 'PII - NRIC',
      severity: 'high',
      status: 'blocked',
      details: 'Attempted to copy patient NRIC S9234567A to clipboard',
      ipAddress: '192.168.1.45'
    },
    { 
      id: 'DLP002', 
      timestamp: '2024-12-12 10:42:15', 
      user: 'Sarah Lee', 
      role: 'patient', 
      action: 'Screenshot', 
      dataType: 'Medical Record',
      severity: 'medium',
      status: 'flagged',
      details: 'Screenshot attempt detected on medical records page',
      ipAddress: '203.45.67.89'
    },
    { 
      id: 'DLP003', 
      timestamp: '2024-12-12 10:38:47', 
      user: 'Rachel Wong', 
      role: 'staff', 
      action: 'Bulk Export', 
      dataType: 'Patient List',
      severity: 'critical',
      status: 'blocked',
      details: 'Attempted to export 500+ patient records without authorization',
      ipAddress: '192.168.1.25'
    },
    { 
      id: 'DLP004', 
      timestamp: '2024-12-12 10:35:12', 
      user: 'Dr. Lim Hui Ling', 
      role: 'doctor', 
      action: 'Print', 
      dataType: 'Prescription',
      severity: 'low',
      status: 'allowed',
      details: 'Printed prescription RX-2024-045 for patient James Tan',
      ipAddress: '192.168.1.46'
    },
    { 
      id: 'DLP005', 
      timestamp: '2024-12-12 10:30:56', 
      user: 'james@example.com', 
      role: 'patient', 
      action: 'Download', 
      dataType: 'Medical Certificate',
      severity: 'low',
      status: 'allowed',
      details: 'Downloaded own medical certificate MC-2024-001',
      ipAddress: '203.45.67.90'
    },
    { 
      id: 'DLP006', 
      timestamp: '2024-12-12 10:28:33', 
      user: 'Amy Pharmacist', 
      role: 'pharmacy', 
      action: 'Share Link', 
      dataType: 'Patient Data',
      severity: 'high',
      status: 'blocked',
      details: 'Attempted to share external link containing patient information',
      ipAddress: '192.168.1.50'
    },
  ];

  const filteredEvents = events.filter(event => {
    const matchesSearch = event.user.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         event.dataType.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         event.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = filterSeverity === 'all' || event.severity === filterSeverity;
    const matchesStatus = filterStatus === 'all' || event.status === filterStatus;
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const stats = {
    totalEvents: events.length,
    blocked: events.filter(e => e.status === 'blocked').length,
    flagged: events.filter(e => e.status === 'flagged').length,
    critical: events.filter(e => e.severity === 'critical').length,
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50';
      case 'high': return 'text-orange-600 bg-orange-50';
      case 'medium': return 'text-yellow-600 bg-yellow-50';
      case 'low': return 'text-blue-600 bg-blue-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'blocked': return 'text-red-600 bg-red-50';
      case 'flagged': return 'text-orange-600 bg-orange-50';
      case 'allowed': return 'text-green-600 bg-green-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'Copy NRIC': return Copy;
      case 'Screenshot': return Eye;
      case 'Bulk Export': return Download;
      case 'Share Link': return Share2;
      default: return Shield;
    }
  };

  return (
    <DashboardLayout role="admin" sidebarItems={sidebarItems} userName="Admin User">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-pink-900 mb-2">Data Loss Prevention Events</h1>
          <p className="text-gray-600">Real-time monitoring of data access and transfer attempts</p>
        </div>

        {/* Stats */}
        <div className="grid md:grid-cols-4 gap-4 mb-6">
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-blue-50 rounded-lg">
                <Shield className="w-6 h-6 text-blue-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">{stats.totalEvents}</p>
                <p className="text-sm text-gray-600">Total Events</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-red-50 rounded-lg">
                <XCircle className="w-6 h-6 text-red-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">{stats.blocked}</p>
                <p className="text-sm text-gray-600">Blocked</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-orange-50 rounded-lg">
                <AlertTriangle className="w-6 h-6 text-orange-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">{stats.flagged}</p>
                <p className="text-sm text-gray-600">Flagged</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-red-50 rounded-lg">
                <AlertTriangle className="w-6 h-6 text-red-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">{stats.critical}</p>
                <p className="text-sm text-gray-600">Critical Severity</p>
              </div>
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="bg-white rounded-lg border border-gray-200 p-4 mb-6">
          <div className="grid md:grid-cols-3 gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
              <input
                type="text"
                placeholder="Search events..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
              />
            </div>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
            >
              <option value="all">All Severity Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
            >
              <option value="all">All Status</option>
              <option value="blocked">Blocked</option>
              <option value="flagged">Flagged</option>
              <option value="allowed">Allowed</option>
            </select>
          </div>
        </div>

        {/* DLP Policy Summary */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
          <div className="flex items-start gap-3">
            <Shield className="w-5 h-5 text-blue-600 mt-0.5" />
            <div className="flex-1">
              <h3 className="text-blue-900 mb-2">Active DLP Policies</h3>
              <div className="grid md:grid-cols-3 gap-3 text-sm">
                <div className="bg-white rounded p-2">
                  <p className="text-gray-900">• NRIC/FIN Copy Prevention</p>
                </div>
                <div className="bg-white rounded p-2">
                  <p className="text-gray-900">• Screenshot Detection</p>
                </div>
                <div className="bg-white rounded p-2">
                  <p className="text-gray-900">• Bulk Export Monitoring</p>
                </div>
                <div className="bg-white rounded p-2">
                  <p className="text-gray-900">• External Link Sharing Block</p>
                </div>
                <div className="bg-white rounded p-2">
                  <p className="text-gray-900">• Print Watermarking</p>
                </div>
                <div className="bg-white rounded p-2">
                  <p className="text-gray-900">• Unauthorized Device Detection</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Events Table */}
        <div className="bg-white rounded-lg border border-gray-200">
          <div className="border-b border-gray-200 p-4 flex items-center justify-between">
            <h2 className="text-pink-900">Recent DLP Events</h2>
            <button className="flex items-center gap-2 px-4 py-2 text-sm text-pink-600 hover:bg-pink-50 rounded-lg">
              <Download className="w-4 h-4" />
              Export Report
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Timestamp</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">User</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Action</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Data Type</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Severity</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Status</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {filteredEvents.map((event) => {
                  const ActionIcon = getActionIcon(event.action);
                  return (
                    <tr key={event.id} className="hover:bg-gray-50">
                      <td className="px-4 py-3 text-sm text-gray-900">
                        {event.timestamp}
                      </td>
                      <td className="px-4 py-3">
                        <p className="text-sm text-gray-900">{event.user}</p>
                        <p className="text-xs text-gray-500">{event.role}</p>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <ActionIcon className="w-4 h-4 text-gray-600" />
                          <span className="text-sm text-gray-900">{event.action}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-900">{event.dataType}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 text-xs rounded-full ${getSeverityColor(event.severity)}`}>
                          {event.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(event.status)}`}>
                          {event.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-600 max-w-xs truncate">
                        {event.details}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}