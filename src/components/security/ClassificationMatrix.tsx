import { Shield, Lock, Eye, EyeOff, AlertCircle, CheckCircle, XCircle, Users, Activity, Database } from 'lucide-react';
import { DashboardLayout } from '../layouts/DashboardLayout';

const sidebarItems = [
  { icon: <Shield className="w-5 h-5" />, label: 'Dashboard', path: '/admin/dashboard' },
  { icon: <Users className="w-5 h-5" />, label: 'User Management', path: '/admin/users' },
  { icon: <Activity className="w-5 h-5" />, label: 'Audit Logs', path: '/admin/audit-logs' },
  { icon: <Database className="w-5 h-5" />, label: 'Backup & Recovery', path: '/admin/backup' },
  { icon: <AlertCircle className="w-5 h-5" />, label: 'Data Retention', path: '/admin/data-retention' },
];

export function ClassificationMatrix() {
  const classifications: DataClassification[] = [
    {
      level: 'Public',
      color: 'bg-gray-100 text-gray-700',
      description: 'Information that can be freely shared',
      examples: ['Clinic operating hours', 'General health tips', 'Public announcements', 'Contact information'],
      accessControl: 'No restrictions',
      encryption: 'In transit only (TLS)',
      masking: 'None',
      auditLevel: 'Basic logging'
    },
    {
      level: 'Internal',
      color: 'bg-blue-100 text-blue-700',
      description: 'Information for internal use only',
      examples: ['Staff schedules', 'Internal procedures', 'Non-sensitive reports', 'Meeting notes'],
      accessControl: 'Authenticated users only',
      encryption: 'At rest + in transit',
      masking: 'None',
      auditLevel: 'Standard logging'
    },
    {
      level: 'Confidential',
      color: 'bg-orange-100 text-orange-700',
      description: 'Sensitive information requiring protection',
      examples: ['Patient names', 'Appointment history', 'Medical certificates', 'Billing records'],
      accessControl: 'Role-based access control (RBAC)',
      encryption: 'AES-256 encryption',
      masking: 'Partial masking available',
      auditLevel: 'Detailed audit trail'
    },
    {
      level: 'Highly Confidential',
      color: 'bg-red-100 text-red-700',
      description: 'Highly sensitive data requiring maximum protection',
      examples: ['NRIC/FIN numbers', 'Medical diagnoses', 'Treatment records', 'Prescriptions', 'Lab results'],
      accessControl: 'Attribute-based access control (ABAC)',
      encryption: 'Field-level AES-256 encryption',
      masking: 'Mandatory data masking',
      auditLevel: 'Immutable audit logs'
    }
  ];

  const dataTypes = [
    { 
      name: 'NRIC/FIN', 
      classification: 'Highly Confidential', 
      icon: User,
      color: 'text-red-600',
      maskingExample: 'S9234***A',
      riskLevel: 'Critical'
    },
    { 
      name: 'Medical Diagnoses', 
      classification: 'Highly Confidential', 
      icon: FileText,
      color: 'text-red-600',
      maskingExample: 'Diagnosis: ████████',
      riskLevel: 'Critical'
    },
    { 
      name: 'Patient Name', 
      classification: 'Confidential', 
      icon: User,
      color: 'text-orange-600',
      maskingExample: 'Sarah L***',
      riskLevel: 'High'
    },
    { 
      name: 'Payment Information', 
      classification: 'Highly Confidential', 
      icon: CreditCard,
      color: 'text-red-600',
      maskingExample: '****-****-****-1234',
      riskLevel: 'Critical'
    },
    { 
      name: 'Contact Details', 
      classification: 'Confidential', 
      icon: User,
      color: 'text-orange-600',
      maskingExample: '98******34',
      riskLevel: 'High'
    },
    { 
      name: 'Appointment History', 
      classification: 'Confidential', 
      icon: Database,
      color: 'text-orange-600',
      maskingExample: 'Visible to authorized staff only',
      riskLevel: 'Medium'
    },
  ];

  const abacRules = [
    {
      subject: 'Doctor',
      resource: 'Patient Medical Record',
      condition: 'Own patients OR Emergency access',
      decision: 'Allow',
      action: 'Read, Write',
    },
    {
      subject: 'Nurse/Staff',
      resource: 'Patient Basic Info',
      condition: 'Scheduled appointment exists',
      decision: 'Allow',
      action: 'Read only',
    },
    {
      subject: 'Patient',
      resource: 'Own Medical Records',
      condition: 'Authenticated',
      decision: 'Allow',
      action: 'Read, Download',
    },
    {
      subject: 'Pharmacist',
      resource: 'Prescriptions',
      condition: 'Status = Approved',
      decision: 'Allow',
      action: 'Read, Dispense',
    },
    {
      subject: 'Any User',
      resource: 'NRIC Full Number',
      condition: 'Admin role OR Data controller',
      decision: 'Conditional',
      action: 'View masked by default',
    },
  ];

  return (
    <DashboardLayout role="admin" sidebarItems={sidebarItems} userName="Admin User">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-pink-900 mb-2">Data Classification Matrix</h1>
          <p className="text-gray-600">Information security levels and access control policies</p>
        </div>

        {/* Classification Levels */}
        <div className="bg-white rounded-lg border border-gray-200 mb-6">
          <div className="border-b border-gray-200 p-4">
            <h2 className="text-pink-900">Classification Levels</h2>
          </div>
          <div className="p-4 space-y-4">
            {classifications.map((classification, index) => (
              <div key={index} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <Shield className="w-6 h-6 text-pink-600" />
                    <div>
                      <span className={`px-3 py-1 rounded-full text-sm ${classification.color}`}>
                        {classification.level}
                      </span>
                      <p className="text-gray-600 mt-2">{classification.description}</p>
                    </div>
                  </div>
                </div>
                <div className="grid md:grid-cols-2 gap-4 mb-3">
                  <div>
                    <p className="text-sm text-gray-700 mb-1">Examples:</p>
                    <ul className="text-sm text-gray-600 space-y-1">
                      {classification.examples.map((example, i) => (
                        <li key={i}>• {example}</li>
                      ))}
                    </ul>
                  </div>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-600">Access Control:</span>
                      <span className="text-gray-900">{classification.accessControl}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Encryption:</span>
                      <span className="text-gray-900">{classification.encryption}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Data Masking:</span>
                      <span className="text-gray-900">{classification.masking}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Audit Level:</span>
                      <span className="text-gray-900">{classification.auditLevel}</span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Data Types & Masking */}
        <div className="bg-white rounded-lg border border-gray-200 mb-6">
          <div className="border-b border-gray-200 p-4">
            <h2 className="text-pink-900">Data Types & Field-Level Masking</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Data Type</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Classification</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Masking Example</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Risk Level</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {dataTypes.map((type, index) => {
                  const Icon = type.icon;
                  return (
                    <tr key={index} className="hover:bg-gray-50">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Icon className={`w-5 h-5 ${type.color}`} />
                          <span className="text-sm text-gray-900">{type.name}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 text-xs rounded-full ${
                          type.classification === 'Highly Confidential' 
                            ? 'bg-red-100 text-red-700' 
                            : 'bg-orange-100 text-orange-700'
                        }`}>
                          {type.classification}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <code className="text-sm bg-gray-100 px-2 py-1 rounded text-gray-900">
                          {type.maskingExample}
                        </code>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 text-xs rounded-full ${
                          type.riskLevel === 'Critical' ? 'bg-red-100 text-red-700' :
                          type.riskLevel === 'High' ? 'bg-orange-100 text-orange-700' :
                          'bg-yellow-100 text-yellow-700'
                        }`}>
                          {type.riskLevel}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* ABAC Rules */}
        <div className="bg-white rounded-lg border border-gray-200 mb-6">
          <div className="border-b border-gray-200 p-4">
            <h2 className="text-pink-900">Attribute-Based Access Control (ABAC) Rules</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Subject</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Resource</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Condition</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Decision</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {abacRules.map((rule, index) => (
                  <tr key={index} className="hover:bg-gray-50">
                    <td className="px-4 py-3 text-sm text-gray-900">{rule.subject}</td>
                    <td className="px-4 py-3 text-sm text-gray-900">{rule.resource}</td>
                    <td className="px-4 py-3 text-sm text-gray-600">{rule.condition}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        rule.decision === 'Allow' ? 'bg-green-100 text-green-700' :
                        rule.decision === 'Deny' ? 'bg-red-100 text-red-700' :
                        'bg-yellow-100 text-yellow-700'
                      }`}>
                        {rule.decision}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-900">{rule.action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Compliance Note */}
        <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <Lock className="w-5 h-5 text-purple-600 mt-0.5" />
            <div>
              <h3 className="text-purple-900 mb-1">Compliance & Best Practices</h3>
              <p className="text-sm text-purple-800 mb-2">
                PinkHealth's data classification system aligns with:
              </p>
              <ul className="text-sm text-purple-800 space-y-1">
                <li>• Singapore Personal Data Protection Act (PDPA)</li>
                <li>• Health Insurance Portability and Accountability Act (HIPAA)</li>
                <li>• ISO/IEC 27001 Information Security Standards</li>
                <li>• NIST Cybersecurity Framework</li>
              </ul>
              <p className="text-sm text-purple-800 mt-2">
                All sensitive data is encrypted, masked where appropriate, and access is logged 
                in immutable audit trails for regulatory compliance and forensic analysis.
              </p>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}