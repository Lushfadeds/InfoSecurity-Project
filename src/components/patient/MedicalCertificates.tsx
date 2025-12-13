import { DashboardLayout } from '../layouts/DashboardLayout';
import { Calendar, FileText, Pill, CreditCard, Upload, User, Clock, Download, Eye } from 'lucide-react';

const sidebarItems = [
  { icon: <Calendar className="w-5 h-5" />, label: 'Dashboard', path: '/patient/dashboard' },
  { icon: <Calendar className="w-5 h-5" />, label: 'Book Appointment', path: '/patient/book-appointment' },
  { icon: <Clock className="w-5 h-5" />, label: 'Appointment History', path: '/patient/appointments' },
  { icon: <FileText className="w-5 h-5" />, label: 'Medical Certificates', path: '/patient/medical-certificates' },
  { icon: <Pill className="w-5 h-5" />, label: 'Prescriptions', path: '/patient/prescriptions' },
  { icon: <CreditCard className="w-5 h-5" />, label: 'Billing & Payment', path: '/patient/billing' },
  { icon: <User className="w-5 h-5" />, label: 'Personal Particulars', path: '/patient/profile' },
  { icon: <Upload className="w-5 h-5" />, label: 'Upload Documents', path: '/patient/upload' },
];

const medicalCertificates = [
  {
    id: 'MC-2024-1210',
    issueDate: '2024-12-10',
    doctor: 'Dr. Sarah Tan',
    condition: 'Acute Upper Respiratory Tract Infection',
    mcDuration: '2 days',
    startDate: '2024-12-10',
    endDate: '2024-12-11',
    status: 'Issued',
    verificationCode: 'MC-PINK-1210-4567',
  },
  {
    id: 'MC-2024-0915',
    issueDate: '2024-09-15',
    doctor: 'Dr. Sarah Tan',
    condition: 'Acute Gastroenteritis',
    mcDuration: '1 day',
    startDate: '2024-09-15',
    endDate: '2024-09-15',
    status: 'Issued',
    verificationCode: 'MC-PINK-0915-2341',
  },
  {
    id: 'MC-2024-0622',
    issueDate: '2024-06-22',
    doctor: 'Dr. Michelle Lee',
    condition: 'Severe Migraine',
    mcDuration: '1 day',
    startDate: '2024-06-22',
    endDate: '2024-06-22',
    status: 'Issued',
    verificationCode: 'MC-PINK-0622-8912',
  },
];

export function MedicalCertificates() {
  return (
    <DashboardLayout role="patient" sidebarItems={sidebarItems} userName="John Doe">
      <div className="max-w-5xl">
        <h1 className="text-gray-900 mb-6">Medical Certificates</h1>

        <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
          <p className="text-blue-800 text-sm">
            <strong>Note:</strong> All medical certificates are digitally signed and can be verified 
            by employers using the verification code. Download as PDF for submission.
          </p>
        </div>

        <div className="grid gap-4">
          {medicalCertificates.map((mc) => (
            <div key={mc.id} className="bg-white rounded-xl border border-gray-200 p-6">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <h3 className="text-gray-900">{mc.id}</h3>
                    <span className="px-2 py-1 bg-green-100 text-green-800 text-xs rounded">
                      {mc.status}
                    </span>
                  </div>
                  <p className="text-gray-600 text-sm">
                    Issued by {mc.doctor} on {new Date(mc.issueDate).toLocaleDateString('en-SG')}
                  </p>
                </div>
                <div className="flex gap-2">
                  <button className="p-2 text-pink-600 hover:bg-pink-50 rounded-lg transition-colors">
                    <Eye className="w-5 h-5" />
                  </button>
                  <button className="p-2 text-pink-600 hover:bg-pink-50 rounded-lg transition-colors">
                    <Download className="w-5 h-5" />
                  </button>
                </div>
              </div>

              <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 p-4 bg-gray-50 rounded-lg">
                <div>
                  <p className="text-gray-600 text-xs mb-1">Condition</p>
                  <p className="text-gray-900 text-sm">{mc.condition}</p>
                </div>
                <div>
                  <p className="text-gray-600 text-xs mb-1">MC Duration</p>
                  <p className="text-gray-900 text-sm">{mc.mcDuration}</p>
                </div>
                <div>
                  <p className="text-gray-600 text-xs mb-1">MC Period</p>
                  <p className="text-gray-900 text-sm">
                    {new Date(mc.startDate).toLocaleDateString('en-SG', { month: 'short', day: 'numeric' })} - {new Date(mc.endDate).toLocaleDateString('en-SG', { month: 'short', day: 'numeric' })}
                  </p>
                </div>
                <div>
                  <p className="text-gray-600 text-xs mb-1">Verification Code</p>
                  <p className="text-gray-900 text-sm font-mono">{mc.verificationCode}</p>
                </div>
              </div>

              <div className="mt-4 flex items-center gap-2 text-xs text-gray-500">
                <span>🔒 Encrypted & digitally signed</span>
                <span>•</span>
                <span>Employer can verify authenticity</span>
              </div>
            </div>
          ))}
        </div>

        {medicalCertificates.length === 0 && (
          <div className="bg-white rounded-xl border border-gray-200 p-12 text-center">
            <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-600">No medical certificates found</p>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
