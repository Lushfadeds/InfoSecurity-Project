import { DashboardLayout } from '../layouts/DashboardLayout';
import { Users, Calendar, CreditCard, Upload, UserPlus, Clock } from 'lucide-react';
import { Link } from 'react-router-dom';

const sidebarItems = [
  { icon: <Users className="w-5 h-5" />, label: 'Dashboard', path: '/staff/dashboard' },
  { icon: <Calendar className="w-5 h-5" />, label: 'Create Appointment', path: '/staff/create-appointment' },
  { icon: <CreditCard className="w-5 h-5" />, label: 'Billing & Invoicing', path: '/staff/billing' },
  { icon: <Upload className="w-5 h-5" />, label: 'Upload Documents', path: '/staff/upload' },
];

const patientQueue = [
  { id: '1', name: 'John Doe', nric: 'S****123A', appointmentTime: '09:00 AM', status: 'Waiting' },
  { id: '2', name: 'Jane Smith', nric: 'S****456B', appointmentTime: '09:30 AM', status: 'In Consultation' },
  { id: '3', name: 'Michael Tan', nric: 'S****789C', appointmentTime: '10:00 AM', status: 'Waiting' },
];

export function StaffDashboard() {
  return (
    <DashboardLayout role="staff" sidebarItems={sidebarItems} userName="Alice Wong">
      <div className="max-w-7xl">
        <h1 className="text-gray-900 mb-6">Staff Dashboard</h1>

        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <Link to="/staff/create-appointment" className="bg-white p-6 rounded-xl border border-gray-200 hover:shadow-lg hover:border-purple-300 transition-all">
            <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mb-4">
              <UserPlus className="w-6 h-6 text-purple-600" />
            </div>
            <h3 className="text-gray-900 mb-1">Register Patient</h3>
            <p className="text-gray-600 text-sm">Create appointment for walk-in</p>
          </Link>

          <Link to="/staff/billing" className="bg-white p-6 rounded-xl border border-gray-200 hover:shadow-lg hover:border-purple-300 transition-all">
            <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mb-4">
              <CreditCard className="w-6 h-6 text-green-600" />
            </div>
            <h3 className="text-gray-900 mb-1">Process Billing</h3>
            <p className="text-gray-600 text-sm">Create invoices & payments</p>
          </Link>

          <Link to="/staff/upload" className="bg-white p-6 rounded-xl border border-gray-200 hover:shadow-lg hover:border-purple-300 transition-all">
            <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-4">
              <Upload className="w-6 h-6 text-blue-600" />
            </div>
            <h3 className="text-gray-900 mb-1">Upload Documents</h3>
            <p className="text-gray-600 text-sm">Scan and upload patient docs</p>
          </Link>

          <div className="bg-white p-6 rounded-xl border border-gray-200">
            <div className="w-12 h-12 bg-pink-100 rounded-lg flex items-center justify-center mb-4">
              <Clock className="w-6 h-6 text-pink-600" />
            </div>
            <h3 className="text-gray-900 mb-1">Queue Status</h3>
            <p className="text-2xl">{patientQueue.length}</p>
            <p className="text-gray-600 text-sm">patients waiting</p>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-gray-900 mb-4">Patient Queue</h2>
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="px-6 py-3 text-left text-gray-700">Patient Name</th>
                <th className="px-6 py-3 text-left text-gray-700">NRIC</th>
                <th className="px-6 py-3 text-left text-gray-700">Appointment Time</th>
                <th className="px-6 py-3 text-left text-gray-700">Status</th>
                <th className="px-6 py-3 text-left text-gray-700">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {patientQueue.map((patient) => (
                <tr key={patient.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 text-gray-900">{patient.name}</td>
                  <td className="px-6 py-4 text-gray-600">{patient.nric}</td>
                  <td className="px-6 py-4 text-gray-600">{patient.appointmentTime}</td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 text-xs rounded ${
                      patient.status === 'In Consultation' ? 'bg-blue-100 text-blue-800' : 'bg-yellow-100 text-yellow-800'
                    }`}>
                      {patient.status}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <button className="text-purple-600 hover:text-purple-700 text-sm">Check-in</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </DashboardLayout>
  );
}
