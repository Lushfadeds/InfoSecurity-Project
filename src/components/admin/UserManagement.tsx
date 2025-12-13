import { Users, Search, Plus, Edit, Trash2, Shield, Activity, Database, AlertCircle } from 'lucide-react';
import { DashboardLayout } from '../layouts/DashboardLayout';
import { useState } from 'react';

const sidebarItems = [
  { icon: <Shield className="w-5 h-5" />, label: 'Dashboard', path: '/admin/dashboard' },
  { icon: <Users className="w-5 h-5" />, label: 'User Management', path: '/admin/users' },
  { icon: <Activity className="w-5 h-5" />, label: 'Audit Logs', path: '/admin/audit-logs' },
  { icon: <Database className="w-5 h-5" />, label: 'Backup & Recovery', path: '/admin/backup' },
  { icon: <AlertCircle className="w-5 h-5" />, label: 'Data Retention', path: '/admin/data-retention' },
];

export function UserManagement() {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRole, setFilterRole] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');

  const users: User[] = [
    { id: 'U001', name: 'Dr. Chen Wei Ming', email: 'chen@clinic.com', role: 'doctor', status: 'active', lastLogin: '2024-12-12 10:30', createdDate: '2023-01-15' },
    { id: 'U002', name: 'Sarah Lee', email: 'sarah@example.com', role: 'patient', status: 'active', lastLogin: '2024-12-12 09:15', createdDate: '2023-06-20' },
    { id: 'U003', name: 'Dr. Lim Hui Ling', email: 'lim@clinic.com', role: 'doctor', status: 'active', lastLogin: '2024-12-11 16:45', createdDate: '2023-02-10' },
    { id: 'U004', name: 'Rachel Wong', email: 'rachel@clinic.com', role: 'staff', status: 'active', lastLogin: '2024-12-12 08:00', createdDate: '2023-03-05' },
    { id: 'U005', name: 'James Tan', email: 'james@example.com', role: 'patient', status: 'inactive', lastLogin: '2024-11-15 14:20', createdDate: '2024-01-10' },
    { id: 'U006', name: 'Amy Pharmacist', email: 'amy@clinic.com', role: 'pharmacy', status: 'active', lastLogin: '2024-12-12 10:00', createdDate: '2023-04-18' },
    { id: 'U007', name: 'Admin User', email: 'admin@clinic.com', role: 'admin', status: 'active', lastLogin: '2024-12-12 07:30', createdDate: '2023-01-01' },
  ];

  const filteredUsers = users.filter(user => {
    const matchesSearch = user.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRole = filterRole === 'all' || user.role === filterRole;
    const matchesStatus = filterStatus === 'all' || user.status === filterStatus;
    return matchesSearch && matchesRole && matchesStatus;
  });

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'admin': return 'bg-purple-100 text-purple-700';
      case 'doctor': return 'bg-blue-100 text-blue-700';
      case 'staff': return 'bg-green-100 text-green-700';
      case 'pharmacy': return 'bg-orange-100 text-orange-700';
      case 'patient': return 'bg-gray-100 text-gray-700';
      default: return 'bg-gray-100 text-gray-700';
    }
  };

  const getStatusBadgeColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-green-100 text-green-700';
      case 'inactive': return 'bg-gray-100 text-gray-700';
      case 'suspended': return 'bg-red-100 text-red-700';
      default: return 'bg-gray-100 text-gray-700';
    }
  };

  return (
    <DashboardLayout role="admin" sidebarItems={sidebarItems} userName="Admin User">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6 flex items-start justify-between">
          <div>
            <h1 className="text-pink-900 mb-2">User Management</h1>
            <p className="text-gray-600">Manage system users and permissions</p>
          </div>
          <button className="flex items-center gap-2 px-4 py-2 bg-pink-600 text-white rounded-lg hover:bg-pink-700">
            <Plus className="w-5 h-5" />
            Add User
          </button>
        </div>

        {/* Stats */}
        <div className="grid md:grid-cols-5 gap-4 mb-6">
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <p className="text-2xl text-gray-900">{users.length}</p>
            <p className="text-sm text-gray-600">Total Users</p>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <p className="text-2xl text-gray-900">{users.filter(u => u.role === 'patient').length}</p>
            <p className="text-sm text-gray-600">Patients</p>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <p className="text-2xl text-gray-900">{users.filter(u => u.role === 'doctor').length}</p>
            <p className="text-sm text-gray-600">Doctors</p>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <p className="text-2xl text-gray-900">{users.filter(u => u.role === 'staff').length}</p>
            <p className="text-sm text-gray-600">Staff</p>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <p className="text-2xl text-gray-900">{users.filter(u => u.status === 'active').length}</p>
            <p className="text-sm text-gray-600">Active</p>
          </div>
        </div>

        {/* Filters */}
        <div className="bg-white rounded-lg border border-gray-200 p-4 mb-6">
          <div className="grid md:grid-cols-3 gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
              <input
                type="text"
                placeholder="Search by name, email, or ID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
              />
            </div>
            <select
              value={filterRole}
              onChange={(e) => setFilterRole(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
            >
              <option value="all">All Roles</option>
              <option value="patient">Patient</option>
              <option value="doctor">Doctor</option>
              <option value="staff">Staff</option>
              <option value="pharmacy">Pharmacy</option>
              <option value="admin">Admin</option>
            </select>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
              <option value="suspended">Suspended</option>
            </select>
          </div>
        </div>

        {/* Users Table */}
        <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">User ID</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Name</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Email</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Role</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Status</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Last Login</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {filteredUsers.map((user) => (
                  <tr key={user.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 text-sm text-gray-900">{user.id}</td>
                    <td className="px-4 py-3">
                      <p className="text-sm text-gray-900">{user.name}</p>
                      <p className="text-xs text-gray-500">Created: {user.createdDate}</p>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600">{user.email}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 text-xs rounded-full ${getRoleBadgeColor(user.role)}`}>
                        {user.role}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 text-xs rounded-full ${getStatusBadgeColor(user.status)}`}>
                        {user.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600">{user.lastLogin}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button className="p-1 hover:bg-gray-200 rounded" title="Edit User">
                          <Edit className="w-4 h-4 text-gray-600" />
                        </button>
                        <button className="p-1 hover:bg-gray-200 rounded" title="Permissions">
                          <Shield className="w-4 h-4 text-gray-600" />
                        </button>
                        {user.status === 'active' ? (
                          <button className="p-1 hover:bg-gray-200 rounded" title="Suspend User">
                            <Trash2 className="w-4 h-4 text-gray-600" />
                          </button>
                        ) : (
                          <button className="p-1 hover:bg-gray-200 rounded" title="Activate User">
                            <UserCheck className="w-4 h-4 text-gray-600" />
                          </button>
                        )}
                        <button className="p-1 hover:bg-gray-200 rounded" title="Delete User">
                          <Trash2 className="w-4 h-4 text-red-600" />
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