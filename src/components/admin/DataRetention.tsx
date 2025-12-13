import { Trash2, Archive, Clock, AlertCircle, FileText, Users, Activity, Database, Shield } from 'lucide-react';
import { DashboardLayout } from '../layouts/DashboardLayout';

const sidebarItems = [
  { icon: <Shield className="w-5 h-5" />, label: 'Dashboard', path: '/admin/dashboard' },
  { icon: <Users className="w-5 h-5" />, label: 'User Management', path: '/admin/users' },
  { icon: <Activity className="w-5 h-5" />, label: 'Audit Logs', path: '/admin/audit-logs' },
  { icon: <Database className="w-5 h-5" />, label: 'Backup & Recovery', path: '/admin/backup' },
  { icon: <AlertCircle className="w-5 h-5" />, label: 'Data Retention', path: '/admin/data-retention' },
];

export function DataRetention() {
  const [selectedPolicy, setSelectedPolicy] = useState<string | null>(null);

  const policies: RetentionPolicy[] = [
    { id: 'POL001', dataType: 'Patient Medical Records', retentionPeriod: '7 years', lastReview: '2024-06-01', nextReview: '2025-06-01', status: 'active', recordCount: 8543 },
    { id: 'POL002', dataType: 'Appointment History', retentionPeriod: '3 years', lastReview: '2024-06-01', nextReview: '2025-06-01', status: 'active', recordCount: 12456 },
    { id: 'POL003', dataType: 'Prescriptions', retentionPeriod: '5 years', lastReview: '2024-06-01', nextReview: '2025-06-01', status: 'active', recordCount: 15234 },
    { id: 'POL004', dataType: 'Billing Records', retentionPeriod: '7 years', lastReview: '2024-06-01', nextReview: '2025-06-01', status: 'active', recordCount: 9876 },
    { id: 'POL005', dataType: 'Audit Logs', retentionPeriod: 'Indefinite', lastReview: '2024-06-01', nextReview: '2025-06-01', status: 'active', recordCount: 45678 },
    { id: 'POL006', dataType: 'Temporary Documents', retentionPeriod: '90 days', lastReview: '2024-06-01', nextReview: '2025-06-01', status: 'active', recordCount: 234 },
  ];

  const dataCategories: DataCategory[] = [
    { category: 'Medical Records', total: 8543, active: 7234, archived: 1200, forDeletion: 109 },
    { category: 'Appointments', total: 12456, active: 10234, archived: 2100, forDeletion: 122 },
    { category: 'Prescriptions', total: 15234, active: 13456, archived: 1678, forDeletion: 100 },
    { category: 'Billing', total: 9876, active: 8234, archived: 1542, forDeletion: 100 },
  ];

  const upcomingDeletions = [
    { dataType: 'Temporary Files', count: 234, scheduledDate: '2024-12-15', size: '450 MB' },
    { dataType: 'Expired Appointments', count: 122, scheduledDate: '2024-12-20', size: '12 MB' },
    { dataType: 'Old Medical Records', count: 109, scheduledDate: '2024-12-31', size: '2.3 GB' },
  ];

  return (
    <DashboardLayout role="admin" sidebarItems={sidebarItems} userName="Admin User">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-pink-900 mb-2">Data Retention & Lifecycle</h1>
          <p className="text-gray-600">Manage data retention policies and compliance</p>
        </div>

        {/* Stats */}
        <div className="grid md:grid-cols-4 gap-4 mb-6">
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-blue-50 rounded-lg">
                <FileText className="w-6 h-6 text-blue-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">{policies.length}</p>
                <p className="text-sm text-gray-600">Active Policies</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-green-50 rounded-lg">
                <Archive className="w-6 h-6 text-green-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">6.5k</p>
                <p className="text-sm text-gray-600">Records Archived</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-orange-50 rounded-lg">
                <Clock className="w-6 h-6 text-orange-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">431</p>
                <p className="text-sm text-gray-600">Pending Deletion</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-purple-50 rounded-lg">
                <AlertCircle className="w-6 h-6 text-purple-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">3</p>
                <p className="text-sm text-gray-600">Policy Reviews Due</p>
              </div>
            </div>
          </div>
        </div>

        <div className="grid lg:grid-cols-3 gap-6 mb-6">
          {/* Data Categories */}
          <div className="lg:col-span-2 bg-white rounded-lg border border-gray-200">
            <div className="border-b border-gray-200 p-4">
              <h2 className="text-pink-900">Data by Category</h2>
            </div>
            <div className="p-4 space-y-4">
              {dataCategories.map((category, index) => (
                <div key={index} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-gray-900">{category.category}</h3>
                    <span className="text-sm text-gray-500">{category.total} total records</span>
                  </div>
                  <div className="grid grid-cols-3 gap-3 text-center">
                    <div className="p-2 bg-green-50 rounded">
                      <p className="text-xl text-green-700">{category.active}</p>
                      <p className="text-xs text-gray-600">Active</p>
                    </div>
                    <div className="p-2 bg-blue-50 rounded">
                      <p className="text-xl text-blue-700">{category.archived}</p>
                      <p className="text-xs text-gray-600">Archived</p>
                    </div>
                    <div className="p-2 bg-red-50 rounded">
                      <p className="text-xl text-red-700">{category.forDeletion}</p>
                      <p className="text-xs text-gray-600">For Deletion</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Upcoming Deletions */}
          <div className="bg-white rounded-lg border border-gray-200">
            <div className="border-b border-gray-200 p-4">
              <h2 className="text-pink-900">Scheduled Deletions</h2>
            </div>
            <div className="divide-y divide-gray-200">
              {upcomingDeletions.map((deletion, index) => (
                <div key={index} className="p-4">
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <p className="text-gray-900">{deletion.dataType}</p>
                      <p className="text-sm text-gray-500">{deletion.count} records</p>
                    </div>
                    <Trash2 className="w-4 h-4 text-red-600" />
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-600">{deletion.size}</span>
                    <span className="text-gray-500">{deletion.scheduledDate}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Retention Policies */}
        <div className="bg-white rounded-lg border border-gray-200">
          <div className="border-b border-gray-200 p-4 flex items-center justify-between">
            <h2 className="text-pink-900">Retention Policies</h2>
            <button className="px-4 py-2 bg-pink-600 text-white rounded-lg hover:bg-pink-700">
              Add Policy
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Policy ID</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Data Type</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Retention Period</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Records</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Last Review</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Next Review</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Status</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {policies.map((policy) => (
                  <tr 
                    key={policy.id} 
                    className={`hover:bg-gray-50 ${selectedPolicy === policy.id ? 'bg-pink-50' : ''}`}
                    onClick={() => setSelectedPolicy(policy.id)}
                  >
                    <td className="px-4 py-3 text-sm text-gray-900">{policy.id}</td>
                    <td className="px-4 py-3 text-sm text-gray-900">{policy.dataType}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Clock className="w-4 h-4 text-gray-400" />
                        <span className="text-sm text-gray-900">{policy.retentionPeriod}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-900">{policy.recordCount.toLocaleString()}</td>
                    <td className="px-4 py-3 text-sm text-gray-600">{policy.lastReview}</td>
                    <td className="px-4 py-3 text-sm text-gray-600">{policy.nextReview}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        policy.status === 'active' ? 'bg-green-100 text-green-700' :
                        policy.status === 'pending' ? 'bg-orange-100 text-orange-700' :
                        'bg-red-100 text-red-700'
                      }`}>
                        {policy.status}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button className="p-1 hover:bg-gray-200 rounded" title="Edit Policy">
                          <Calendar className="w-4 h-4 text-gray-600" />
                        </button>
                        <button className="p-1 hover:bg-gray-200 rounded" title="Archive">
                          <Archive className="w-4 h-4 text-gray-600" />
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