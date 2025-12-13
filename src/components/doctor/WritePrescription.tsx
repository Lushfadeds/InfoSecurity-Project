import { DashboardLayout } from '../layouts/DashboardLayout';
import { Stethoscope, Search, FileText, Pill, User, Plus, Trash2, Save } from 'lucide-react';
import { useState } from 'react';

const sidebarItems = [
  { icon: <Stethoscope className="w-5 h-5" />, label: 'Dashboard', path: '/doctor/dashboard' },
  { icon: <Search className="w-5 h-5" />, label: 'Patient Lookup', path: '/doctor/patient-lookup' },
  { icon: <FileText className="w-5 h-5" />, label: 'Start Consultation', path: '/doctor/consultation' },
  { icon: <FileText className="w-5 h-5" />, label: 'Write MC', path: '/doctor/write-mc' },
  { icon: <Pill className="w-5 h-5" />, label: 'Write Prescription', path: '/doctor/write-prescription' },
  { icon: <User className="w-5 h-5" />, label: 'My Profile', path: '/doctor/profile' },
];

export function WritePrescription() {
  const [medications, setMedications] = useState([
    { name: '', dosage: '', frequency: '', duration: '', instructions: '' }
  ]);

  const addMedication = () => {
    setMedications([...medications, { name: '', dosage: '', frequency: '', duration: '', instructions: '' }]);
  };

  const removeMedication = (index: number) => {
    setMedications(medications.filter((_, i) => i !== index));
  };

  return (
    <DashboardLayout role="doctor" sidebarItems={sidebarItems} userName="Dr. Sarah Tan">
      <div className="max-w-5xl">
        <h1 className="text-gray-900 mb-6">Write Prescription</h1>

        <div className="bg-white rounded-xl border border-gray-200 p-6 mb-6">
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
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-gray-900">Medications</h2>
            <button
              onClick={addMedication}
              className="flex items-center gap-2 px-4 py-2 text-blue-600 hover:bg-blue-50 rounded-lg"
            >
              <Plus className="w-4 h-4" />
              Add Medication
            </button>
          </div>

          <div className="space-y-4">
            {medications.map((med, index) => (
              <div key={index} className="p-4 bg-gray-50 rounded-lg border border-gray-200">
                <div className="flex items-start justify-between mb-3">
                  <h3 className="text-gray-700">Medication #{index + 1}</h3>
                  {medications.length > 1 && (
                    <button
                      onClick={() => removeMedication(index)}
                      className="text-red-600 hover:bg-red-50 p-1 rounded"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>

                <div className="grid sm:grid-cols-2 gap-3">
                  <div className="sm:col-span-2">
                    <label className="block text-gray-700 text-sm mb-2">Medication Name *</label>
                    <input
                      type="text"
                      placeholder="e.g., Amoxicillin 500mg"
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-gray-700 text-sm mb-2">Dosage *</label>
                    <input
                      type="text"
                      placeholder="e.g., 1 capsule"
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-gray-700 text-sm mb-2">Frequency *</label>
                    <select className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                      <option>Once daily</option>
                      <option>Twice daily</option>
                      <option>3 times daily</option>
                      <option>4 times daily</option>
                      <option>As needed</option>
                      <option>Every 6 hours</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-gray-700 text-sm mb-2">Duration *</label>
                    <input
                      type="text"
                      placeholder="e.g., 7 days"
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-gray-700 text-sm mb-2">Instructions</label>
                    <input
                      type="text"
                      placeholder="e.g., Take after meals"
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg text-sm text-blue-800">
            <p>🔒 Prescription will be encrypted and automatically sent to pharmacy for dispensing.</p>
          </div>

          <div className="mt-6 flex gap-3">
            <button className="flex-1 px-6 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50">
              Cancel
            </button>
            <button className="flex-1 px-6 py-3 bg-blue-500 text-white rounded-lg hover:bg-blue-600 flex items-center justify-center gap-2">
              <Save className="w-5 h-5" />
              Generate Prescription
            </button>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
