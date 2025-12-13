import { DashboardLayout } from '../layouts/DashboardLayout';
import { Stethoscope, Search, FileText, Pill, User, Upload, Save } from 'lucide-react';
import { useState } from 'react';

const sidebarItems = [
  { icon: <Stethoscope className="w-5 h-5" />, label: 'Dashboard', path: '/doctor/dashboard' },
  { icon: <Search className="w-5 h-5" />, label: 'Patient Lookup', path: '/doctor/patient-lookup' },
  { icon: <FileText className="w-5 h-5" />, label: 'Start Consultation', path: '/doctor/consultation' },
  { icon: <FileText className="w-5 h-5" />, label: 'Write MC', path: '/doctor/write-mc' },
  { icon: <Pill className="w-5 h-5" />, label: 'Write Prescription', path: '/doctor/write-prescription' },
  { icon: <User className="w-5 h-5" />, label: 'My Profile', path: '/doctor/profile' },
];

export function ConsultationPage() {
  const [diagnosis, setDiagnosis] = useState('');
  const [notes, setNotes] = useState('');
  const [treatmentPlan, setTreatmentPlan] = useState('');

  return (
    <DashboardLayout role="doctor" sidebarItems={sidebarItems} userName="Dr. Sarah Tan">
      <div className="max-w-5xl">
        <h1 className="text-gray-900 mb-6">Consultation</h1>

        <div className="grid lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <h2 className="text-gray-900 mb-4">Patient Information</h2>
              <div className="grid sm:grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-gray-600 mb-1">Patient Name</p>
                  <p className="text-gray-900">John Doe</p>
                </div>
                <div>
                  <p className="text-gray-600 mb-1">NRIC</p>
                  <p className="text-gray-900">S****123A</p>
                </div>
                <div>
                  <p className="text-gray-600 mb-1">Age / Gender</p>
                  <p className="text-gray-900">34 years / Male</p>
                </div>
                <div>
                  <p className="text-gray-600 mb-1">Contact</p>
                  <p className="text-gray-900">+65 9123 4567</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <h2 className="text-gray-900 mb-4">Consultation Notes</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-gray-700 text-sm mb-2">Diagnosis *</label>
                  <input
                    type="text"
                    value={diagnosis}
                    onChange={(e) => setDiagnosis(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="e.g., Acute Upper Respiratory Tract Infection"
                  />
                </div>

                <div>
                  <label className="block text-gray-700 text-sm mb-2">Clinical Notes *</label>
                  <textarea
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    rows={6}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Patient presents with symptoms of... Examination reveals..."
                  />
                  <p className="text-xs text-gray-500 mt-1">🔒 Notes will be encrypted upon saving</p>
                </div>

                <div>
                  <label className="block text-gray-700 text-sm mb-2">Treatment Plan</label>
                  <textarea
                    value={treatmentPlan}
                    onChange={(e) => setTreatmentPlan(e.target.value)}
                    rows={4}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Prescribed medications, follow-up instructions..."
                  />
                </div>

                <div>
                  <label className="block text-gray-700 text-sm mb-2">Upload Related Documents</label>
                  <div className="border-2 border-dashed border-gray-300 rounded-lg p-4 text-center">
                    <Upload className="w-8 h-8 text-gray-400 mx-auto mb-2" />
                    <p className="text-sm text-gray-600">Upload lab results, X-rays, etc.</p>
                    <button className="mt-2 px-4 py-2 text-blue-600 hover:bg-blue-50 rounded text-sm">
                      Select Files
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex gap-3">
              <button className="flex-1 px-6 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50">
                Cancel
              </button>
              <button className="flex-1 px-6 py-3 bg-blue-500 text-white rounded-lg hover:bg-blue-600 flex items-center justify-center gap-2">
                <Save className="w-5 h-5" />
                Save Consultation
              </button>
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <h3 className="text-gray-900 mb-4">Quick Actions</h3>
              <div className="space-y-2">
                <a href="/doctor/write-mc" className="block px-4 py-2 text-center bg-purple-50 text-purple-700 rounded-lg hover:bg-purple-100">
                  Issue MC
                </a>
                <a href="/doctor/write-prescription" className="block px-4 py-2 text-center bg-pink-50 text-pink-700 rounded-lg hover:bg-pink-100">
                  Write Prescription
                </a>
              </div>
            </div>

            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <h3 className="text-gray-900 mb-4">Previous Visits</h3>
              <div className="space-y-3 text-sm">
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-gray-900 mb-1">Dec 10, 2023</p>
                  <p className="text-gray-600">Annual checkup</p>
                </div>
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-gray-900 mb-1">Jun 15, 2023</p>
                  <p className="text-gray-600">Flu symptoms</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
