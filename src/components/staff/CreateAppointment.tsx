import { DashboardLayout } from '../layouts/DashboardLayout';
import { Users, Calendar, CreditCard, Upload } from 'lucide-react';

const sidebarItems = [
  { icon: <Users className="w-5 h-5" />, label: 'Dashboard', path: '/staff/dashboard' },
  { icon: <Calendar className="w-5 h-5" />, label: 'Create Appointment', path: '/staff/create-appointment' },
  { icon: <CreditCard className="w-5 h-5" />, label: 'Billing & Invoicing', path: '/staff/billing' },
  { icon: <Upload className="w-5 h-5" />, label: 'Upload Documents', path: '/staff/upload' },
];

export function CreateAppointment() {
  return (
    <DashboardLayout role="staff" sidebarItems={sidebarItems} userName="Alice Wong">
      <div className="max-w-4xl">
        <h1 className="text-gray-900 mb-6">Create Appointment (Walk-in)</h1>

        <div className="bg-white rounded-xl border border-gray-200 p-6 mb-6">
          <h2 className="text-gray-900 mb-4">Patient Search</h2>
          <div className="flex gap-3">
            <input
              type="text"
              placeholder="Search by name, NRIC, or phone..."
              className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500"
            />
            <button className="px-6 py-2 bg-purple-500 text-white rounded-lg hover:bg-purple-600">
              Search
            </button>
          </div>
          <p className="text-sm text-gray-500 mt-2">Note: NRIC displayed as S****123A for privacy (DLP masking)</p>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-gray-900 mb-4">Appointment Details</h2>
          <div className="space-y-4">
            <div className="grid sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-gray-700 text-sm mb-2">Patient Name *</label>
                <input type="text" className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500" />
              </div>
              <div>
                <label className="block text-gray-700 text-sm mb-2">NRIC *</label>
                <input type="text" className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500" />
              </div>
              <div>
                <label className="block text-gray-700 text-sm mb-2">Select Doctor *</label>
                <select className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500">
                  <option>Dr. Sarah Tan - General Practitioner</option>
                  <option>Dr. James Wong - Cardiologist</option>
                  <option>Dr. Michelle Lee - Dermatologist</option>
                </select>
              </div>
              <div>
                <label className="block text-gray-700 text-sm mb-2">Appointment Time *</label>
                <select className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500">
                  <option>Next Available (10:30 AM)</option>
                  <option>11:00 AM</option>
                  <option>11:30 AM</option>
                </select>
              </div>
            </div>
            <div>
              <label className="block text-gray-700 text-sm mb-2">Reason for Visit</label>
              <textarea rows={3} className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500" />
            </div>
            <button className="w-full px-6 py-3 bg-purple-500 text-white rounded-lg hover:bg-purple-600">
              Create Appointment
            </button>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
