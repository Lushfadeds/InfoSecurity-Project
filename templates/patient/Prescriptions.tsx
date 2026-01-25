import { DashboardLayout } from '../layouts/DashboardLayout';
import { Home, Calendar, FileText, Pill, CreditCard, User, Upload, Download, Shield, RefreshCw } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { tokenizePrescription } from '../../utils/dataMaskingService';
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

const prescriptions = [
  {
    id: 'RX-2024-1210',
    date: '2024-12-10',
    doctor: 'Dr. Sarah Tan',
    medications: [
      { name: 'Amoxicillin 500mg', dosage: '1 capsule', frequency: '3 times daily', duration: '7 days', instructions: 'Take after meals' },
      { name: 'Paracetamol 500mg', dosage: '1-2 tablets', frequency: 'Every 6 hours as needed', duration: '7 days', instructions: 'For fever or pain' },
    ],
    status: 'Dispensed',
    dispensedDate: '2024-12-10',
    validUntil: '2025-06-10',
  },
  {
    id: 'RX-2024-1122',
    date: '2024-11-22',
    doctor: 'Dr. James Wong',
    medications: [
      { name: 'Amlodipine 5mg', dosage: '1 tablet', frequency: 'Once daily', duration: '30 days', instructions: 'Take in the morning' },
      { name: 'Atorvastatin 20mg', dosage: '1 tablet', frequency: 'Once daily at night', duration: '30 days', instructions: 'Take before bedtime' },
    ],
    status: 'Active',
    dispensedDate: '2024-11-22',
    validUntil: '2025-05-22',
  },
];

export function Prescriptions() {
  const handleDownloadPrescription = (rx: typeof prescriptions[0]) => {
    // Generate prescription content
    const pdfContent = `
PINKHEALTH MEDICAL CENTRE
Prescription
----------------------------------------

Prescription ID: ${rx.id}
Date: ${new Date(rx.date).toLocaleDateString('en-SG', { year: 'numeric', month: 'long', day: 'numeric' })}

Patient: John Doe
NRIC: S****567A

Prescribed by: ${rx.doctor}
License No: SMC-12345

MEDICATIONS:
${rx.medications.map((med, idx) => `
${idx + 1}. ${med.name}
   Dosage: ${med.dosage}
   Frequency: ${med.frequency}
   Duration: ${med.duration}
   Instructions: ${med.instructions}
`).join('\n')}

Status: ${rx.status}
Dispensed: ${new Date(rx.dispensedDate).toLocaleDateString('en-SG', { year: 'numeric', month: 'long', day: 'numeric' })}
Valid Until: ${new Date(rx.validUntil).toLocaleDateString('en-SG', { year: 'numeric', month: 'long', day: 'numeric' })}

----------------------------------------
IMPORTANT NOTES:
- Take medications as prescribed
- Complete the full course of antibiotics
- Do not share medications with others
- Store in a cool, dry place

Digital Signature: ✓ VERIFIED
Encrypted: ✓ AES-256

This is a computer-generated document.
    `.trim();

    // Create blob and download
    const blob = new Blob([pdfContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Prescription_${rx.id}_${rx.date}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toast.success('Prescription downloaded successfully', {
      description: `${rx.id} saved to your downloads folder`
    });
  };

  return (
    <DashboardLayout role="patient" sidebarItems={sidebarItems} userName="John Doe">
      <div className="max-w-5xl">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-gray-900">Prescriptions</h1>
        </div>

        <div className="mb-6 p-4 bg-pink-50 border border-pink-200 rounded-lg flex items-start gap-3">
          <Shield className="w-5 h-5 text-pink-600 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-pink-800">
            <p className="mb-1"><strong>Prescription Tokenization Active</strong></p>
            <p>Prescription IDs are tokenized in system logs and analytics to protect your privacy. Your medication information remains encrypted and accessible only to authorized healthcare providers.</p>
          </div>
        </div>

        <div className="grid gap-4">
          {prescriptions.map((rx) => (
            <div key={rx.id} className="bg-white rounded-xl border border-gray-200 p-6">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <h3 className="text-gray-900">{tokenizePrescription(rx.id)}</h3>
                    <span className={`px-2 py-1 text-xs rounded ${
                      rx.status === 'Dispensed' ? 'bg-blue-100 text-blue-800' : 'bg-green-100 text-green-800'
                    }`}>
                      {rx.status}
                    </span>
                  </div>
                  <p className="text-gray-600 text-sm">
                    Prescribed by {rx.doctor} on {new Date(rx.date).toLocaleDateString('en-SG')}
                  </p>
                </div>
                <div className="flex gap-2">
                  <Link
                    to={`/patient/request-refill?rx=${rx.id}`}
                    className="px-3 py-2 text-pink-600 border border-pink-300 rounded-lg hover:bg-pink-50 text-sm flex items-center gap-2"
                  >
                    <RefreshCw className="w-4 h-4" />
                    Request Refill
                  </Link>
                  <button 
                    onClick={() => handleDownloadPrescription(rx)}
                    className="p-2 text-pink-600 hover:bg-pink-50 rounded-lg"
                    title="Download prescription"
                  >
                    <Download className="w-5 h-5" />
                  </button>
                </div>
              </div>

              <div className="space-y-3">
                {rx.medications.map((med, index) => (
                  <div key={index} className="p-4 bg-gray-50 rounded-lg">
                    <div className="flex items-start justify-between mb-2">
                      <h4 className="text-gray-900">{med.name}</h4>
                    </div>
                    <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3 text-sm">
                      <div>
                        <p className="text-gray-600 text-xs">Dosage</p>
                        <p className="text-gray-900">{med.dosage}</p>
                      </div>
                      <div>
                        <p className="text-gray-600 text-xs">Frequency</p>
                        <p className="text-gray-900">{med.frequency}</p>
                      </div>
                      <div>
                        <p className="text-gray-600 text-xs">Duration</p>
                        <p className="text-gray-900">{med.duration}</p>
                      </div>
                      <div>
                        <p className="text-gray-600 text-xs">Instructions</p>
                        <p className="text-gray-900">{med.instructions}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-4 flex items-center justify-between text-sm">
                <div className="flex items-center gap-4 text-gray-600">
                  <span>Dispensed: {new Date(rx.dispensedDate).toLocaleDateString('en-SG')}</span>
                  <span>Valid until: {new Date(rx.validUntil).toLocaleDateString('en-SG')}</span>
                </div>
                <span className="text-xs text-gray-500">🔒 Encrypted prescription</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </DashboardLayout>
  );
}