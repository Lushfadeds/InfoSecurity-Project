import { Database, Download, Upload, Clock, CheckCircle, AlertCircle, Users, Activity, Shield } from 'lucide-react';
import { DashboardLayout } from '../layouts/DashboardLayout';

const sidebarItems = [
  { icon: <Shield className="w-5 h-5" />, label: 'Dashboard', path: '/admin/dashboard' },
  { icon: <Users className="w-5 h-5" />, label: 'User Management', path: '/admin/users' },
  { icon: <Activity className="w-5 h-5" />, label: 'Audit Logs', path: '/admin/audit-logs' },
  { icon: <Database className="w-5 h-5" />, label: 'Backup & Recovery', path: '/admin/backup' },
  { icon: <AlertCircle className="w-5 h-5" />, label: 'Data Retention', path: '/admin/data-retention' },
];

export function BackupRecovery() {
  const [isBackingUp, setIsBackingUp] = useState(false);

  const backups: Backup[] = [
    { id: 'BKP001', timestamp: '2024-12-12 02:00:00', type: 'automatic', size: '2.4 GB', status: 'completed', location: 'AWS S3 - Singapore', retentionDate: '2025-12-12' },
    { id: 'BKP002', timestamp: '2024-12-11 02:00:00', type: 'automatic', size: '2.3 GB', status: 'completed', location: 'AWS S3 - Singapore', retentionDate: '2025-12-11' },
    { id: 'BKP003', timestamp: '2024-12-10 14:30:00', type: 'manual', size: '2.3 GB', status: 'completed', location: 'AWS S3 - Singapore', retentionDate: '2025-12-10' },
    { id: 'BKP004', timestamp: '2024-12-10 02:00:00', type: 'automatic', size: '2.2 GB', status: 'completed', location: 'AWS S3 - Singapore', retentionDate: '2025-12-10' },
    { id: 'BKP005', timestamp: '2024-12-09 02:00:00', type: 'automatic', size: '2.2 GB', status: 'completed', location: 'AWS S3 - Singapore', retentionDate: '2025-12-09' },
  ];

  const backupConfig = {
    frequency: 'Daily at 2:00 AM SGT',
    retention: '365 days',
    encryption: 'AES-256',
    location: 'AWS S3 - ap-southeast-1',
    replication: 'Multi-region (Singapore + Tokyo)',
  };

  const handleBackup = () => {
    setIsBackingUp(true);
    setTimeout(() => {
      setIsBackingUp(false);
      alert('Manual backup initiated successfully');
    }, 2000);
  };

  return (
    <DashboardLayout role="admin" sidebarItems={sidebarItems} userName="Admin User">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-pink-900 mb-2">Backup & Recovery</h1>
          <p className="text-gray-600">Manage data backups and disaster recovery</p>
        </div>

        {/* Stats */}
        <div className="grid md:grid-cols-4 gap-4 mb-6">
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-green-50 rounded-lg">
                <CheckCircle className="w-6 h-6 text-green-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">{backups.filter(b => b.status === 'completed').length}</p>
                <p className="text-sm text-gray-600">Successful Backups</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-blue-50 rounded-lg">
                <Database className="w-6 h-6 text-blue-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">2.4 GB</p>
                <p className="text-sm text-gray-600">Latest Backup Size</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-purple-50 rounded-lg">
                <Clock className="w-6 h-6 text-purple-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">365</p>
                <p className="text-sm text-gray-600">Retention Days</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-orange-50 rounded-lg">
                <RefreshCw className="w-6 h-6 text-orange-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">12h</p>
                <p className="text-sm text-gray-600">Last Backup</p>
              </div>
            </div>
          </div>
        </div>

        <div className="grid lg:grid-cols-3 gap-6 mb-6">
          {/* Quick Actions */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-pink-900 mb-4">Quick Actions</h2>
            <div className="space-y-3">
              <button
                onClick={handleBackup}
                disabled={isBackingUp}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-pink-600 text-white rounded-lg hover:bg-pink-700 disabled:bg-gray-300"
              >
                {isBackingUp ? (
                  <>
                    <RefreshCw className="w-5 h-5 animate-spin" />
                    Backing Up...
                  </>
                ) : (
                  <>
                    <Database className="w-5 h-5" />
                    Initiate Manual Backup
                  </>
                )}
              </button>
              <button className="w-full flex items-center justify-center gap-2 px-4 py-3 border border-gray-300 rounded-lg hover:bg-gray-50">
                <Upload className="w-5 h-5" />
                Restore from Backup
              </button>
              <button className="w-full flex items-center justify-center gap-2 px-4 py-3 border border-gray-300 rounded-lg hover:bg-gray-50">
                <Download className="w-5 h-5" />
                Download Backup
              </button>
            </div>
          </div>

          {/* Backup Configuration */}
          <div className="lg:col-span-2 bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-pink-900 mb-4">Backup Configuration</h2>
            <div className="space-y-3">
              <div className="flex justify-between py-2 border-b border-gray-200">
                <span className="text-gray-600">Backup Frequency</span>
                <span className="text-gray-900">{backupConfig.frequency}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-gray-200">
                <span className="text-gray-600">Retention Period</span>
                <span className="text-gray-900">{backupConfig.retention}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-gray-200">
                <span className="text-gray-600">Encryption</span>
                <span className="text-gray-900">{backupConfig.encryption}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-gray-200">
                <span className="text-gray-600">Storage Location</span>
                <span className="text-gray-900">{backupConfig.location}</span>
              </div>
              <div className="flex justify-between py-2">
                <span className="text-gray-600">Replication</span>
                <span className="text-gray-900">{backupConfig.replication}</span>
              </div>
            </div>
            <button className="mt-4 px-4 py-2 text-pink-600 hover:bg-pink-50 rounded-lg">
              Edit Configuration
            </button>
          </div>
        </div>

        {/* Backup History */}
        <div className="bg-white rounded-lg border border-gray-200">
          <div className="border-b border-gray-200 p-4">
            <h2 className="text-pink-900">Backup History</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Backup ID</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Timestamp</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Type</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Size</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Location</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Status</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {backups.map((backup) => (
                  <tr key={backup.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 text-sm text-gray-900">{backup.id}</td>
                    <td className="px-4 py-3 text-sm text-gray-600">{backup.timestamp}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        backup.type === 'automatic' ? 'bg-blue-100 text-blue-700' : 'bg-purple-100 text-purple-700'
                      }`}>
                        {backup.type}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-900">{backup.size}</td>
                    <td className="px-4 py-3 text-sm text-gray-600">{backup.location}</td>
                    <td className="px-4 py-3">
                      <span className={`flex items-center gap-1 text-sm ${
                        backup.status === 'completed' ? 'text-green-600' :
                        backup.status === 'in-progress' ? 'text-blue-600' : 'text-red-600'
                      }`}>
                        {backup.status === 'completed' && <CheckCircle className="w-4 h-4" />}
                        {backup.status === 'in-progress' && <RefreshCw className="w-4 h-4 animate-spin" />}
                        {backup.status === 'failed' && <AlertCircle className="w-4 h-4" />}
                        {backup.status}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button className="p-1 hover:bg-gray-200 rounded" title="Restore">
                          <Upload className="w-4 h-4 text-gray-600" />
                        </button>
                        <button className="p-1 hover:bg-gray-200 rounded" title="Download">
                          <Download className="w-4 h-4 text-gray-600" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}