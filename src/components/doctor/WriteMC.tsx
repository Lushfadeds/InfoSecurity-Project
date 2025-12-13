import { DashboardLayout } from '../layouts/DashboardLayout';
import { Stethoscope, Search, FileText, Pill, User, Eye, Save } from 'lucide-react';
import { useState } from 'react';

const sidebarItems = [
  { icon: <Stethoscope className="w-5 h-5" />, label: 'Dashboard', path: '/doctor/dashboard' },
  { icon: <Search className="w-5 h-5" />, label: 'Patient Lookup', path: '/doctor/patient-lookup' },
  { icon: <FileText className="w-5 h-5" />, label: 'Start Consultation', path: '/doctor/consultation' },
  { icon: <FileText className="w-5 h-5" />, label: 'Write MC', path: '/doctor/write-mc' },
  { icon: <Pill className="w-5 h-5" />, label: 'Write Prescription', path: '/doctor/write-prescription' },
  { icon: <User className="w-5 h-5" />, label: 'My Profile', path: '/doctor/profile' },
];

export function WriteMC() {
  const [mcDuration, setMcDuration] = useState('1');
  const [startDate, setStartDate] = useState(new Date().toISOString().split('T')[0]);
  const [condition, setCondition] = useState('');

  return (
    <DashboardLayout role="doctor" sidebarItems={sidebarItems} userName="Dr. Sarah Tan">
      <div className="max-w-4xl">
        <h1 className="text-gray-900 mb-6">Issue Medical Certificate</h1>

        <div className="grid lg:grid-cols-2 gap-6">
          <div className="space-y-6">
            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <h2 className="text-gray-900 mb-4">Patient Details</h2>
              <div className="space-y-3 text-sm">
                <div>
                  <p className="text-gray-600 mb-1">Patient Name</p>
                  <input
                    type="text"
                    defaultValue="John Doe"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <p className="text-gray-600 mb-1">NRIC</p>
                  <p className="text-gray-900 px-4 py-2 bg-gray-50 rounded-lg">S****123A</p>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <h2 className="text-gray-900 mb-4">MC Details</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-gray-700 text-sm mb-2">Condition / Diagnosis *</label>
                  <input
                    type="text"
                    value={condition}
                    onChange={(e) => setCondition(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="e.g., Acute Upper Respiratory Tract Infection"
                  />
                </div>

                <div>
                  <label className="block text-gray-700 text-sm mb-2">Start Date *</label>
                  <input
                    type="date"
                    value={startDate}
                    onChange={(e) => setStartDate(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-gray-700 text-sm mb-2">MC Duration *</label>
                  <select
                    value={mcDuration}
                    onChange={(e) => setMcDuration(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="1">1 day</option>
                    <option value="2">2 days</option>
                    <option value="3">3 days</option>
                    <option value="4">4 days</option>
                    <option value="5">5 days</option>
                    <option value="7">1 week</option>
                  </select>
                </div>

                <div className="p-3 bg-gray-50 rounded-lg text-sm">
                  <p className="text-gray-600">End Date (calculated)</p>
                  <p className="text-gray-900">{new Date(new Date(startDate).setDate(new Date(startDate).getDate() + parseInt(mcDuration) - 1)).toLocaleDateString('en-SG')}</p>
                </div>
              </div>
            </div>

            <div className="flex gap-3">
              <button className="flex-1 px-6 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50">
                Cancel
              </button>
              <button className="flex-1 px-6 py-3 bg-blue-500 text-white rounded-lg hover:bg-blue-600 flex items-center justify-center gap-2">
                <Save className="w-5 h-5" />
                Issue MC
              </button>
            </div>
          </div>

          <div className="bg-white rounded-xl border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-gray-900">Preview</h2>
              <Eye className="w-5 h-5 text-gray-400" />
            </div>
            <div className="border border-gray-300 rounded-lg p-6 bg-gray-50 min-h-[500px]">
              <div className="text-center mb-6">
                <h3 className="text-lg">MEDICAL CERTIFICATE</h3>
                <p className="text-sm text-gray-600 mt-2">PinkHealth Medical Centre</p>
              </div>
              <div className="space-y-4 text-sm">
                <p>This is to certify that:</p>
                <div className="pl-4">
                  <p><strong>Patient Name:</strong> John Doe</p>
                  <p><strong>NRIC:</strong> S****123A</p>
                </div>
                <p>was examined and found to be suffering from:</p>
                <div className="pl-4">
                  <p className="italic">{condition || '[Condition]'}</p>
                </div>
                <p>and is unfit for duty from:</p>
                <div className="pl-4">
                  <p>{new Date(startDate).toLocaleDateString('en-SG')} to {new Date(new Date(startDate).setDate(new Date(startDate).getDate() + parseInt(mcDuration) - 1)).toLocaleDateString('en-SG')}</p>
                  <p>({mcDuration} day{mcDuration !== '1' ? 's' : ''})</p>
                </div>
                <div className="mt-8 pt-4 border-t border-gray-300">
                  <p><strong>Dr. Sarah Tan</strong></p>
                  <p className="text-xs text-gray-600">General Practitioner</p>
                  <p className="text-xs text-gray-600 mt-2">Date: {new Date().toLocaleDateString('en-SG')}</p>
                  <p className="text-xs text-gray-500 mt-4">🔒 Digitally signed & encrypted</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
