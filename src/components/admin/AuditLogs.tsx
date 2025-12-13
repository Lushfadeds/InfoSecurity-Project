import { Activity, Search, Filter, Download, Eye, AlertCircle, Users, Database, Shield } from 'lucide-react';
import { DashboardLayout } from '../layouts/DashboardLayout';
import { useState } from 'react';

const sidebarItems = [
  { icon: <Shield className="w-5 h-5" />, label: 'Dashboard', path: '/admin/dashboard' },
  { icon: <Users className="w-5 h-5" />, label: 'User Management', path: '/admin/users' },
  { icon: <Activity className="w-5 h-5" />, label: 'Audit Logs', path: '/admin/audit-logs' },
  { icon: <Database className="w-5 h-5" />, label: 'Backup & Recovery', path: '/admin/backup' },
  { icon: <AlertCircle className="w-5 h-5" />, label: 'Data Retention', path: '/admin/data-retention' },
];

export function AuditLogs() {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterAction, setFilterAction] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [dateRange, setDateRange] = useState('today');

  const logs: AuditLog[] = [
    { id: 'LOG001', timestamp: '2024-12-12 10:45:23', user: 'Dr. Chen Wei Ming', role: 'doctor', action: 'VIEW', resource: 'Patient Record - Sarah Lee', ipAddress: '192.168.1.45', status: 'success', details: 'Accessed patient medical history' },
    { id: 'LOG002', timestamp: '2024-12-12 10:42:15', user: 'Sarah Lee', role: 'patient', action: 'DOWNLOAD', resource: 'Medical Certificate MC-2024-001', ipAddress: '203.45.67.89', status: 'success', details: 'Downloaded MC document' },
    { id: 'LOG003', timestamp: '2024-12-12 10:38:47', user: 'Admin User', role: 'admin', action: 'CREATE', resource: 'User Account - Rachel Wong', ipAddress: '192.168.1.10', status: 'success', details: 'Created new staff account' },
    { id: 'LOG004', timestamp: '2024-12-12 10:35:12', user: 'james@example.com', role: 'patient', action: 'LOGIN', resource: 'Authentication System', ipAddress: '203.45.67.90', status: 'failed', details: 'Invalid password attempt (3/5)' },
    { id: 'LOG005', timestamp: '2024-12-12 10:30:56', user: 'Dr. Lim Hui Ling', role: 'doctor', action: 'UPDATE', resource: 'Prescription RX-2024-045', ipAddress: '192.168.1.46', status: 'success', details: 'Modified medication dosage' },
    { id: 'LOG006', timestamp: '2024-12-12 10:28:33', user: 'Rachel Wong', role: 'staff', action: 'EXPORT', resource: 'Billing Report - November 2024', ipAddress: '192.168.1.25', status: 'warning', details: 'Exported sensitive financial data' },
    { id: 'LOG007', timestamp: '2024-12-12 10:25:18', user: 'Amy Pharmacist', role: 'pharmacy', action: 'DISPENSE', resource: 'Prescription RX-2024-044', ipAddress: '192.168.1.50', status: 'success', details: 'Dispensed medication to patient' },
  ];

  const filteredLogs = logs.filter(log => {
    const matchesSearch = log.user.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         log.resource.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         log.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesAction = filterAction === 'all' || log.action === filterAction;
    const matchesStatus = filterStatus === 'all' || log.status === filterStatus;
    return matchesSearch && matchesAction && matchesStatus;
  });

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'VIEW': return Eye;
      case 'LOGIN': return Users;
      case 'DOWNLOAD': case 'EXPORT': return Download;
      case 'CREATE': case 'UPDATE': return Database;
      default: return Shield;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success': return 'text-green-600 bg-green-50';
      case 'failed': return 'text-red-600 bg-red-50';
      case 'warning': return 'text-orange-600 bg-orange-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  return (
    <DashboardLayout role="admin" sidebarItems={sidebarItems} userName="Admin User">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6 flex items-start justify-between">
          <div>
            <h1 className="text-pink-900 mb-2">Audit Logs</h1>
            <p className="text-gray-600">Immutable record of all system activities</p>
          </div>
          <button className="flex items-center gap-2 px-4 py-2 bg-pink-600 text-white rounded-lg hover:bg-pink-700">
            <Download className="w-5 h-5" />
            Export Logs
          </button>
        </div>

        {/* Stats */}
        <div className="grid md:grid-cols-4 gap-4 mb-6">
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <p className="text-2xl text-gray-900">{logs.length}</p>
            <p className="text-sm text-gray-600">Total Events Today</p>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <p className="text-2xl text-green-600">{logs.filter(l => l.status === 'success').length}</p>
            <p className="text-sm text-gray-600">Successful</p>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <p className="text-2xl text-red-600">{logs.filter(l => l.status === 'failed').length}</p>
            <p className="text-sm text-gray-600">Failed</p>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <p className="text-2xl text-orange-600">{logs.filter(l => l.status === 'warning').length}</p>
            <p className="text-sm text-gray-600">Warnings</p>
          </div>
        </div>

        {/* Filters */}
        <div className="bg-white rounded-lg border border-gray-200 p-4 mb-6">
          <div className="grid md:grid-cols-4 gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
              <input
                type="text"
                placeholder="Search logs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
              />
            </div>
            <select
              value={filterAction}
              onChange={(e) => setFilterAction(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
            >
              <option value="all">All Actions</option>
              <option value="VIEW">View</option>
              <option value="CREATE">Create</option>
              <option value="UPDATE">Update</option>
              <option value="DELETE">Delete</option>
              <option value="DOWNLOAD">Download</option>
              <option value="EXPORT">Export</option>
              <option value="LOGIN">Login</option>
            </select>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
            >
              <option value="all">All Status</option>
              <option value="success">Success</option>
              <option value="failed">Failed</option>
              <option value="warning">Warning</option>
            </select>
            <select
              value={dateRange}
              onChange={(e) => setDateRange(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
            >
              <option value="today">Today</option>
              <option value="week">This Week</option>
              <option value="month">This Month</option>
              <option value="custom">Custom Range</option>
            </select>
          </div>
        </div>

        {/* Logs Table */}
        <div className="bg-white rounded-lg border border-gray-200">
          <div className="border-b border-gray-200 p-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Lock className="w-5 h-5 text-pink-600" />
              <h2 className="text-pink-900">Immutable Audit Trail</h2>
            </div>
            <span className="text-sm text-gray-500">Blockchain-verified records</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Timestamp</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">User</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Action</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Resource</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">IP Address</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {filteredLogs.map((log) => {
                  const ActionIcon = getActionIcon(log.action);
                  return (
                    <tr key={log.id} className="hover:bg-gray-50">
                      <td className="px-4 py-3 text-sm text-gray-900">
                        {log.timestamp}
                      </td>
                      <td className="px-4 py-3">
                        <p className="text-sm text-gray-900">{log.user}</p>
                        <p className="text-xs text-gray-500">{log.role}</p>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <ActionIcon className="w-4 h-4 text-gray-600" />
                          <span className="text-sm text-gray-900">{log.action}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <p className="text-sm text-gray-900">{log.resource}</p>
                        <p className="text-xs text-gray-500">{log.details}</p>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-600">
                        {log.ipAddress}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(log.status)}`}>
                          {log.status}
                        </span>
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