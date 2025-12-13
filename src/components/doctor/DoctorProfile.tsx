import { DashboardLayout } from '../layouts/DashboardLayout';
import { Stethoscope, Search, FileText, Pill, User, Edit2, Save } from 'lucide-react';
import { useState } from 'react';

const sidebarItems = [
  { icon: <Stethoscope className="w-5 h-5" />, label: 'Dashboard', path: '/doctor/dashboard' },
  { icon: <Search className="w-5 h-5" />, label: 'Patient Lookup', path: '/doctor/patient-lookup' },
  { icon: <FileText className="w-5 h-5" />, label: 'Start Consultation', path: '/doctor/consultation' },
  { icon: <FileText className="w-5 h-5" />, label: 'Write MC', path: '/doctor/write-mc' },
  { icon: <Pill className="w-5 h-5" />, label: 'Write Prescription', path: '/doctor/write-prescription' },
  { icon: <User className="w-5 h-5" />, label: 'My Profile', path: '/doctor/profile' },
];

export function DoctorProfile() {
  const [isEditing, setIsEditing] = useState(false);

  return (
    <DashboardLayout role="doctor" sidebarItems={sidebarItems} userName="Dr. Sarah Tan">
      <div className="max-w-4xl">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-gray-900">My Profile</h1>
          {!isEditing ? (
            <button
              onClick={() => setIsEditing(true)}
              className="flex items-center gap-2 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
            >
              <Edit2 className="w-4 h-4" />
              Edit Profile
            </button>
          ) : (
            <div className="flex gap-2">
              <button
                onClick={() => setIsEditing(false)}
                className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={() => setIsEditing(false)}
                className="flex items-center gap-2 px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600"
              >
                <Save className="w-4 h-4" />
                Save Changes
              </button>
            </div>
          )}
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6 mb-6">
          <h2 className="text-gray-900 mb-4">Professional Information</h2>
          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-gray-700 text-sm mb-2">Full Name</label>
              <input
                type="text"
                defaultValue="Dr. Sarah Tan"
                disabled={!isEditing}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-50"
              />
            </div>
            <div>
              <label className="block text-gray-700 text-sm mb-2">Specialty</label>
              <input
                type="text"
                defaultValue="General Practitioner"
                disabled={!isEditing}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-50"
              />
            </div>
            <div>
              <label className="block text-gray-700 text-sm mb-2">MCR Number</label>
              <input
                type="text"
                defaultValue="M12345"
                disabled
                className="w-full px-4 py-2 border border-gray-300 rounded-lg bg-gray-50"
              />
            </div>
            <div>
              <label className="block text-gray-700 text-sm mb-2">Email</label>
              <input
                type="email"
                defaultValue="sarah.tan@pinkhealth.sg"
                disabled={!isEditing}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-50"
              />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-gray-900 mb-4">Availability Schedule</h2>
          <div className="space-y-3">
            {['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'].map((day) => (
              <div key={day} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <span className="text-gray-900">{day}</span>
                <div className="flex items-center gap-4">
                  <input type="time" defaultValue="09:00" disabled={!isEditing} className="px-2 py-1 border border-gray-300 rounded disabled:bg-white" />
                  <span className="text-gray-600">to</span>
                  <input type="time" defaultValue="17:00" disabled={!isEditing} className="px-2 py-1 border border-gray-300 rounded disabled:bg-white" />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
