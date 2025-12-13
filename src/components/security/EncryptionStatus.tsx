import { Lock, Shield, Key, CheckCircle, Database, HardDrive, FileText, Cloud, Users, Activity, AlertCircle } from 'lucide-react';
import { DashboardLayout } from '../layouts/DashboardLayout';

const sidebarItems = [
  { icon: <Shield className="w-5 h-5" />, label: 'Dashboard', path: '/admin/dashboard' },
  { icon: <Users className="w-5 h-5" />, label: 'User Management', path: '/admin/users' },
  { icon: <Activity className="w-5 h-5" />, label: 'Audit Logs', path: '/admin/audit-logs' },
  { icon: <Database className="w-5 h-5" />, label: 'Backup & Recovery', path: '/admin/backup' },
  { icon: <AlertCircle className="w-5 h-5" />, label: 'Data Retention', path: '/admin/data-retention' },
];

export function EncryptionStatus() {
  const encryptionStatus = {
    overall: 'Fully Encrypted',
    algorithm: 'AES-256-GCM',
    keyManagement: 'AWS KMS with Hardware Security Module (HSM)',
    certificateExpiry: '2025-12-31',
    lastKeyRotation: '2024-11-01',
    nextKeyRotation: '2025-02-01',
  };

  const dataCategories = [
    { 
      name: 'Patient Data (At Rest)', 
      status: 'encrypted', 
      method: 'AES-256-GCM', 
      icon: Database,
      details: 'Full database encryption with automated key rotation'
    },
    { 
      name: 'Data in Transit', 
      status: 'encrypted', 
      method: 'TLS 1.3', 
      icon: Cloud,
      details: 'All network traffic encrypted with latest TLS protocol'
    },
    { 
      name: 'File Storage', 
      status: 'encrypted', 
      method: 'AES-256-CBC', 
      icon: HardDrive,
      details: 'Document storage with per-file encryption keys'
    },
    { 
      name: 'Backup Data', 
      status: 'encrypted', 
      method: 'AES-256-GCM', 
      icon: FileText,
      details: 'Encrypted backups with separate key hierarchy'
    },
    { 
      name: 'API Communications', 
      status: 'encrypted', 
      method: 'TLS 1.3 + JWT', 
      icon: Shield,
      details: 'End-to-end encryption for all API requests'
    },
    { 
      name: 'User Credentials', 
      status: 'encrypted', 
      method: 'Argon2id', 
      icon: Key,
      details: 'Password hashing with salt and memory-hard algorithm'
    },
  ];

  const keyManagement = [
    { key: 'Master Key', status: 'Active', location: 'AWS KMS HSM', rotation: 'Quarterly', lastRotation: '2024-11-01' },
    { key: 'Database Encryption Key', status: 'Active', location: 'AWS KMS', rotation: 'Monthly', lastRotation: '2024-12-01' },
    { key: 'File Encryption Key', status: 'Active', location: 'AWS KMS', rotation: 'Monthly', lastRotation: '2024-12-01' },
    { key: 'Backup Encryption Key', status: 'Active', location: 'AWS KMS', rotation: 'Quarterly', lastRotation: '2024-11-01' },
  ];

  const securityCertificates = [
    { type: 'SSL/TLS Certificate', issuer: 'Let\'s Encrypt', expiry: '2025-03-15', status: 'Valid' },
    { type: 'Code Signing Certificate', issuer: 'DigiCert', expiry: '2025-06-30', status: 'Valid' },
    { type: 'API Certificate', issuer: 'AWS Certificate Manager', expiry: '2025-12-31', status: 'Valid' },
  ];

  return (
    <DashboardLayout role="admin" sidebarItems={sidebarItems} userName="Admin User">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-pink-900 mb-2">Encryption Status</h1>
          <p className="text-gray-600">End-to-end encryption and key management overview</p>
        </div>

        {/* Overall Status */}
        <div className="bg-gradient-to-r from-green-500 to-green-600 rounded-lg p-6 mb-6 text-white">
          <div className="flex items-center gap-4 mb-4">
            <div className="p-4 bg-white/20 rounded-lg">
              <Lock className="w-8 h-8" />
            </div>
            <div>
              <h2 className="text-2xl mb-1">{encryptionStatus.overall}</h2>
              <p className="text-green-100">All data encrypted with industry-standard algorithms</p>
            </div>
          </div>
          <div className="grid md:grid-cols-3 gap-4 pt-4 border-t border-white/20">
            <div>
              <p className="text-green-100 text-sm">Encryption Algorithm</p>
              <p className="text-lg">{encryptionStatus.algorithm}</p>
            </div>
            <div>
              <p className="text-green-100 text-sm">Last Key Rotation</p>
              <p className="text-lg">{encryptionStatus.lastKeyRotation}</p>
            </div>
            <div>
              <p className="text-green-100 text-sm">Next Key Rotation</p>
              <p className="text-lg">{encryptionStatus.nextKeyRotation}</p>
            </div>
          </div>
        </div>

        {/* Data Categories */}
        <div className="bg-white rounded-lg border border-gray-200 mb-6">
          <div className="border-b border-gray-200 p-4">
            <h2 className="text-pink-900">Encryption by Data Category</h2>
          </div>
          <div className="p-4 grid md:grid-cols-2 gap-4">
            {dataCategories.map((category, index) => {
              const Icon = category.icon;
              return (
                <div key={index} className="border border-gray-200 rounded-lg p-4 hover:border-pink-300 transition-colors">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-green-50 rounded-lg">
                        <Icon className="w-5 h-5 text-green-600" />
                      </div>
                      <div>
                        <p className="text-gray-900">{category.name}</p>
                        <p className="text-sm text-gray-500">{category.method}</p>
                      </div>
                    </div>
                    <CheckCircle className="w-5 h-5 text-green-600" />
                  </div>
                  <p className="text-sm text-gray-600">{category.details}</p>
                </div>
              );
            })}
          </div>
        </div>

        <div className="grid lg:grid-cols-2 gap-6 mb-6">
          {/* Key Management */}
          <div className="bg-white rounded-lg border border-gray-200">
            <div className="border-b border-gray-200 p-4">
              <h2 className="text-pink-900">Key Management</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-4 py-3 text-left text-sm text-gray-700">Key Type</th>
                    <th className="px-4 py-3 text-left text-sm text-gray-700">Status</th>
                    <th className="px-4 py-3 text-left text-sm text-gray-700">Location</th>
                    <th className="px-4 py-3 text-left text-sm text-gray-700">Rotation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {keyManagement.map((key, index) => (
                    <tr key={index} className="hover:bg-gray-50">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Key className="w-4 h-4 text-gray-400" />
                          <span className="text-sm text-gray-900">{key.key}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-1 text-xs rounded-full bg-green-100 text-green-700">
                          {key.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-600">{key.location}</td>
                      <td className="px-4 py-3">
                        <p className="text-sm text-gray-900">{key.rotation}</p>
                        <p className="text-xs text-gray-500">Last: {key.lastRotation}</p>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Security Certificates */}
          <div className="bg-white rounded-lg border border-gray-200">
            <div className="border-b border-gray-200 p-4">
              <h2 className="text-pink-900">Security Certificates</h2>
            </div>
            <div className="p-4 space-y-3">
              {securityCertificates.map((cert, index) => (
                <div key={index} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <p className="text-gray-900">{cert.type}</p>
                      <p className="text-sm text-gray-500">Issued by {cert.issuer}</p>
                    </div>
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      cert.status === 'Valid' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                    }`}>
                      {cert.status}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-gray-600">Expires: {cert.expiry}</span>
                    <Shield className="w-4 h-4 text-green-600" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Compliance Note */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <Shield className="w-5 h-5 text-blue-600 mt-0.5" />
            <div>
              <h3 className="text-blue-900 mb-1">Compliance & Standards</h3>
              <p className="text-sm text-blue-800">
                PinkHealth encryption practices comply with HIPAA, PDPA (Singapore), ISO 27001, 
                and industry best practices for healthcare data security. All encryption keys are 
                stored in hardware security modules (HSM) and undergo regular rotation.
              </p>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}