import { DashboardLayout } from '../layouts/DashboardLayout';
import { Home, Calendar, FileText, Pill, CreditCard, User, Upload, Download, Eye, Shield, X, CheckCircle } from 'lucide-react';
import { useState } from 'react';
import { tokenizeMedicalCertificate } from '../../utils/dataMaskingService';
import { toast } from '../ui/simple-toast';

const sidebarItems = [
  { icon: <Home className="w-5 h-5" />, label: 'Home', path: '/patient/dashboard' },
  { icon: <Calendar className="w-5 h-5" />, label: 'Book Appointment', path: '/patient/book-appointment' },
  { icon: <Calendar className="w-5 h-5" />, label: 'Appointment History', path: '/patient/appointments' },
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
  const [viewingMC, setViewingMC] = useState<typeof medicalCertificates[0] | null>(null);

  const handleViewMC = (mc: typeof medicalCertificates[0]) => {
    setViewingMC(mc);
  };

  const handleDownloadMC = (mc: typeof medicalCertificates[0]) => {
    // Generate PDF content
    const pdfContent = `
PINKHEALTH MEDICAL CENTRE
Medical Certificate
----------------------------------------

Certificate ID: ${mc.id}
Verification Code: ${mc.verificationCode}
Issue Date: ${new Date(mc.issueDate).toLocaleDateString('en-SG', { year: 'numeric', month: 'long', day: 'numeric' })}

Patient: John Doe
NRIC: S****567A

This is to certify that the above patient was examined and found to be suffering from:
${mc.condition}

Medical Certificate Period:
From: ${new Date(mc.startDate).toLocaleDateString('en-SG', { year: 'numeric', month: 'long', day: 'numeric' })}
To: ${new Date(mc.endDate).toLocaleDateString('en-SG', { year: 'numeric', month: 'long', day: 'numeric' })}
Duration: ${mc.mcDuration}

The patient is advised to rest during this period.

Issued by: ${mc.doctor}
License No: SMC-12345

Digital Signature: ✓ VERIFIED
Encrypted: ✓ AES-256

----------------------------------------
This is a computer-generated document.
Verify authenticity at: verify.pinkhealth.sg
    `.trim();

    // Create blob and download
    const blob = new Blob([pdfContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `MC_${mc.id}_${mc.issueDate}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toast.success('Medical Certificate downloaded successfully', {
      description: `${mc.id} saved to your downloads folder`
    });
  };

  return (
    <DashboardLayout role="patient" sidebarItems={sidebarItems} userName="John Doe">
      <div className="max-w-5xl">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-gray-900">Medical Certificates</h1>
        </div>

        <div className="mb-6 p-4 bg-pink-50 border border-pink-200 rounded-lg flex items-start gap-3">
          <Shield className="w-5 h-5 text-pink-600 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-pink-800">
            <p className="mb-1"><strong>Document Tokenization Active</strong></p>
            <p>Medical certificate IDs are tokenized in system logs and analytics to protect your privacy. All certificates are digitally signed and can be verified by employers using the verification code.</p>
          </div>
        </div>

        <div className="grid gap-4">
          {medicalCertificates.map((mc) => (
            <div key={mc.id} className="bg-white rounded-xl border border-gray-200 p-6">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <h3 className="text-gray-900">{tokenizeMedicalCertificate(mc.id)}</h3>
                    <span className="px-2 py-1 bg-green-100 text-green-800 text-xs rounded">
                      {mc.status}
                    </span>
                  </div>
                  <p className="text-gray-600 text-sm">
                    Issued by {mc.doctor} on {new Date(mc.issueDate).toLocaleDateString('en-SG')}
                  </p>
                </div>
                <div className="flex gap-2">
                  <button 
                    onClick={() => handleViewMC(mc)}
                    className="p-2 text-pink-600 hover:bg-pink-50 rounded-lg transition-colors"
                    title="View certificate"
                  >
                    <Eye className="w-5 h-5" />
                  </button>
                  <button 
                    onClick={() => handleDownloadMC(mc)}
                    className="p-2 text-pink-600 hover:bg-pink-50 rounded-lg transition-colors"
                    title="Download certificate"
                  >
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

      {/* View MC Modal */}
      {viewingMC && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="sticky top-0 bg-white border-b border-gray-200 p-6 flex items-center justify-between">
              <h2 className="text-gray-900">Medical Certificate</h2>
              <button 
                onClick={() => setViewingMC(null)}
                className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <X className="w-5 h-5 text-gray-500" />
              </button>
            </div>
            
            <div className="p-6">
              {/* Official MC Document */}
              <div className="border-2 border-pink-500 rounded-lg p-8 bg-gradient-to-br from-white to-pink-50">
                <div className="text-center mb-6">
                  <h3 className="text-2xl text-pink-600 mb-2">PINKHEALTH MEDICAL CENTRE</h3>
                  <p className="text-gray-600">123 Health Street, Singapore 123456</p>
                  <p className="text-gray-600">Tel: +65 6123 4567</p>
                </div>

                <div className="border-t-2 border-b-2 border-pink-300 py-4 my-6 text-center">
                  <h4 className="text-xl text-gray-900">MEDICAL CERTIFICATE</h4>
                </div>

                <div className="space-y-4 mb-6">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-xs text-gray-600">Certificate ID:</p>
                      <p className="text-gray-900 font-mono">{tokenizeMedicalCertificate(viewingMC.id)}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-600">Issue Date:</p>
                      <p className="text-gray-900">{new Date(viewingMC.issueDate).toLocaleDateString('en-SG', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-xs text-gray-600">Patient Name:</p>
                      <p className="text-gray-900">John Doe</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-600">NRIC:</p>
                      <p className="text-gray-900 font-mono">S****567A</p>
                    </div>
                  </div>

                  <div className="bg-white p-4 rounded-lg border border-gray-200">
                    <p className="text-sm text-gray-600 mb-2">This is to certify that the above patient was examined and found to be suffering from:</p>
                    <p className="text-gray-900">{viewingMC.condition}</p>
                  </div>

                  <div className="bg-white p-4 rounded-lg border border-gray-200">
                    <p className="text-xs text-gray-600 mb-2">Medical Certificate Period:</p>
                    <div className="grid grid-cols-3 gap-4">
                      <div>
                        <p className="text-xs text-gray-500">From</p>
                        <p className="text-gray-900">{new Date(viewingMC.startDate).toLocaleDateString('en-SG')}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">To</p>
                        <p className="text-gray-900">{new Date(viewingMC.endDate).toLocaleDateString('en-SG')}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">Duration</p>
                        <p className="text-gray-900">{viewingMC.mcDuration}</p>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gray-50 p-4 rounded-lg">
                    <p className="text-sm text-gray-700 italic">The patient is advised to rest during this period.</p>
                  </div>
                </div>

                <div className="border-t border-gray-300 pt-4 mt-6">
                  <div className="flex justify-between items-end">
                    <div>
                      <p className="text-sm text-gray-600">Issued by:</p>
                      <p className="text-gray-900">{viewingMC.doctor}</p>
                      <p className="text-xs text-gray-500">License No: SMC-12345</p>
                    </div>
                    <div className="text-right">
                      <div className="flex items-center gap-2 text-green-600 mb-1">
                        <CheckCircle className="w-4 h-4" />
                        <span className="text-sm">Digitally Signed</span>
                      </div>
                      <p className="text-xs text-gray-500">Encrypted: AES-256</p>
                    </div>
                  </div>
                </div>

                <div className="mt-6 p-3 bg-blue-50 border border-blue-200 rounded-lg">
                  <p className="text-xs text-blue-800">
                    <strong>Verification Code:</strong> {viewingMC.verificationCode}
                  </p>
                  <p className="text-xs text-blue-700 mt-1">
                    Employers can verify authenticity at: verify.pinkhealth.sg
                  </p>
                </div>
              </div>

              <div className="mt-6 flex gap-3">
                <button
                  onClick={() => handleDownloadMC(viewingMC)}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600"
                >
                  <Download className="w-5 h-5" />
                  Download Certificate
                </button>
                <button
                  onClick={() => setViewingMC(null)}
                  className="px-4 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </DashboardLayout>
  );
}