import { Users, Activity, Shield, Database, AlertCircle, TrendingUp } from 'lucide-react';
import { DashboardLayout } from '../layouts/DashboardLayout';

const sidebarItems = [
  { icon: <Shield className="w-5 h-5" />, label: 'Dashboard', path: '/admin/dashboard' },
  { icon: <Users className="w-5 h-5" />, label: 'User Management', path: '/admin/users' },
  { icon: <Activity className="w-5 h-5" />, label: 'Audit Logs', path: '/admin/audit-logs' },
  { icon: <Database className="w-5 h-5" />, label: 'Backup & Recovery', path: '/admin/backup' },
  { icon: <AlertCircle className="w-5 h-5" />, label: 'Data Retention', path: '/admin/data-retention' },
];

export function AdminDashboard() {
  const stats = [
    { label: 'Total Users', value: '1,248', change: '+12%', icon: Users, color: 'text-blue-600', bg: 'bg-blue-50' },
    { label: 'Active Sessions', value: '156', change: '+5%', icon: Activity, color: 'text-green-600', bg: 'bg-green-50' },
    { label: 'Security Events', value: '23', change: '-8%', icon: Shield, color: 'text-orange-600', bg: 'bg-orange-50' },
    { label: 'Storage Used', value: '1.2 TB', change: '+15%', icon: Database, color: 'text-purple-600', bg: 'bg-purple-50' },
  ];

  const recentActivity = [
    { user: 'Dr. Chen Wei Ming', action: 'Accessed patient record', time: '2 mins ago', type: 'access' },
    { user: 'Sarah Lee (Patient)', action: 'Downloaded medical certificate', time: '5 mins ago', type: 'download' },
    { user: 'Admin User', action: 'Created new staff account', time: '10 mins ago', type: 'admin' },
    { user: 'System', action: 'Automated backup completed', time: '15 mins ago', type: 'system' },
  ];

  const securityAlerts = [
    { severity: 'high', message: 'Multiple failed login attempts detected', user: 'james.tan@example.com', time: '5 mins ago' },
    { severity: 'medium', message: 'Data export request for sensitive records', user: 'Dr. Lim', time: '20 mins ago' },
    { severity: 'low', message: 'Password policy update required', user: 'staff@clinic.com', time: '1 hour ago' },
  ];

  const systemHealth = [
    { name: 'Database', status: 'healthy', uptime: '99.9%' },
    { name: 'API Server', status: 'healthy', uptime: '99.8%' },
    { name: 'File Storage', status: 'warning', uptime: '98.5%' },
    { name: 'Backup System', status: 'healthy', uptime: '100%' },
  ];

  return (
    <DashboardLayout role="admin" sidebarItems={sidebarItems} userName="Admin User">
      <div className="mb-6">
        <h1 className="text-pink-900 mb-2">Admin Dashboard</h1>
        <p className="text-gray-600">System overview and management</p>
      </div>

      {/* Stats Grid */}
      <div className="grid md:grid-cols-4 gap-4 mb-6">
        {stats.map((stat, index) => (
          <div key={index} className="bg-white rounded-lg border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-4">
              <div className={`p-3 rounded-lg ${stat.bg}`}>
                <stat.icon className={`w-6 h-6 ${stat.color}`} />
              </div>
              <span className={`text-sm ${
                stat.change.startsWith('+') ? 'text-green-600' : 'text-red-600'
              }`}>
                {stat.change}
              </span>
            </div>
            <p className="text-3xl text-gray-900 mb-1">{stat.value}</p>
            <p className="text-sm text-gray-600">{stat.label}</p>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-2 gap-6 mb-6">
        {/* Recent Activity */}
        <div className="bg-white rounded-lg border border-gray-200">
          <div className="border-b border-gray-200 p-4 flex items-center justify-between">
            <h2 className="text-pink-900">Recent Activity</h2>
            <a href="/admin/audit-logs" className="text-sm text-pink-600 hover:text-pink-700">
              View All
            </a>
          </div>
          <div className="divide-y divide-gray-200">
            {recentActivity.map((activity, index) => (
              <div key={index} className="p-4 hover:bg-gray-50">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <p className="text-gray-900">{activity.user}</p>
                    <p className="text-sm text-gray-600">{activity.action}</p>
                  </div>
                  <span className="text-xs text-gray-500">{activity.time}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Security Alerts */}
        <div className="bg-white rounded-lg border border-gray-200">
          <div className="border-b border-gray-200 p-4 flex items-center justify-between">
            <h2 className="text-pink-900">Security Alerts</h2>
            <a href="/security/dlp-events" className="text-sm text-pink-600 hover:text-pink-700">
              View All
            </a>
          </div>
          <div className="divide-y divide-gray-200">
            {securityAlerts.map((alert, index) => (
              <div key={index} className="p-4 hover:bg-gray-50">
                <div className="flex items-start gap-3">
                  <AlertCircle className={`w-5 h-5 mt-0.5 ${
                    alert.severity === 'high' ? 'text-red-600' :
                    alert.severity === 'medium' ? 'text-orange-600' : 'text-yellow-600'
                  }`} />
                  <div className="flex-1">
                    <p className="text-gray-900">{alert.message}</p>
                    <p className="text-sm text-gray-600 mt-1">
                      {alert.user} • {alert.time}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* System Health */}
      <div className="bg-white rounded-lg border border-gray-200">
        <div className="border-b border-gray-200 p-4">
          <h2 className="text-pink-900">System Health</h2>
        </div>
        <div className="grid md:grid-cols-4 gap-4 p-4">
          {systemHealth.map((system, index) => (
            <div key={index} className="p-4 border border-gray-200 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <p className="text-gray-900">{system.name}</p>
                <span className={`w-2 h-2 rounded-full ${
                  system.status === 'healthy' ? 'bg-green-500' :
                  system.status === 'warning' ? 'bg-orange-500' : 'bg-red-500'
                }`} />
              </div>
              <p className="text-sm text-gray-600">Uptime: {system.uptime}</p>
            </div>
          ))}
        </div>
      </div>
    </DashboardLayout>
  );
}