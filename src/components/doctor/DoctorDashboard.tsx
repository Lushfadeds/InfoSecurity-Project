import { DashboardLayout } from '../layouts/DashboardLayout';
import { Stethoscope, Search, FileText, Pill, User, Calendar, Clock, AlertCircle } from 'lucide-react';
import { Link } from 'react-router-dom';

const sidebarItems = [
  { icon: <Stethoscope className="w-5 h-5" />, label: 'Dashboard', path: '/doctor/dashboard' },
  { icon: <Search className="w-5 h-5" />, label: 'Patient Lookup', path: '/doctor/patient-lookup' },
  { icon: <FileText className="w-5 h-5" />, label: 'Start Consultation', path: '/doctor/consultation' },
  { icon: <FileText className="w-5 h-5" />, label: 'Write MC', path: '/doctor/write-mc' },
  { icon: <Pill className="w-5 h-5" />, label: 'Write Prescription', path: '/doctor/write-prescription' },
  { icon: <User className="w-5 h-5" />, label: 'My Profile', path: '/doctor/profile' },
];

const todaysAppointments = [
  { id: '1', time: '09:00 AM', patient: 'John Doe', nric: 'S****123A', reason: 'General consultation', status: 'Confirmed' },
  { id: '2', time: '09:30 AM', patient: 'Jane Smith', nric: 'S****456B', reason: 'Follow-up', status: 'Checked-in' },
  { id: '3', time: '10:00 AM', patient: 'Michael Tan', nric: 'S****789C', reason: 'Flu symptoms', status: 'Confirmed' },
  { id: '4', time: '10:30 AM', patient: 'Sarah Lee', nric: 'S****234D', reason: 'General consultation', status: 'Confirmed' },
];

const pendingTasks = [
  { message: 'Sign MC for John Doe (consultation completed)', link: '/doctor/write-mc' },
  { message: '2 lab results ready for review', link: '/doctor/patient-lookup' },
];

export function DoctorDashboard() {
  return (
    <DashboardLayout role="doctor" sidebarItems={sidebarItems} userName="Dr. Sarah Tan">
      <div className="max-w-7xl">
        <div className="mb-8">
          <h1 className="text-gray-900 mb-2">Good morning, Dr. Tan</h1>
          <p className="text-gray-600">General Practitioner</p>
        </div>

        {/* Pending Tasks */}
        {pendingTasks.length > 0 && (
          <div className="mb-6 space-y-3">
            {pendingTasks.map((task, index) => (
              <div key={index} className="flex items-start gap-3 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                <AlertCircle className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
                <div className="flex-1">
                  <p className="text-gray-800">{task.message}</p>
                </div>
                <Link to={task.link} className="text-blue-600 hover:text-blue-700 flex-shrink-0">
                  View →
                </Link>
              </div>
            ))}
          </div>
        )}

        {/* Quick Actions */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <Link
            to="/doctor/patient-lookup"
            className="bg-white p-6 rounded-xl border border-gray-200 hover:shadow-lg hover:border-blue-300 transition-all"
          >
            <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-4">
              <Search className="w-6 h-6 text-blue-600" />
            </div>
            <h3 className="text-gray-900 mb-1">Patient Lookup</h3>
            <p className="text-gray-600 text-sm">Search patient records</p>
          </Link>

          <Link
            to="/doctor/consultation"
            className="bg-white p-6 rounded-xl border border-gray-200 hover:shadow-lg hover:border-blue-300 transition-all"
          >
            <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mb-4">
              <FileText className="w-6 h-6 text-green-600" />
            </div>
            <h3 className="text-gray-900 mb-1">Start Consultation</h3>
            <p className="text-gray-600 text-sm">Begin patient consultation</p>
          </Link>

          <Link
            to="/doctor/write-mc"
            className="bg-white p-6 rounded-xl border border-gray-200 hover:shadow-lg hover:border-blue-300 transition-all"
          >
            <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mb-4">
              <FileText className="w-6 h-6 text-purple-600" />
            </div>
            <h3 className="text-gray-900 mb-1">Write MC</h3>
            <p className="text-gray-600 text-sm">Issue medical certificate</p>
          </Link>

          <Link
            to="/doctor/write-prescription"
            className="bg-white p-6 rounded-xl border border-gray-200 hover:shadow-lg hover:border-blue-300 transition-all"
          >
            <div className="w-12 h-12 bg-pink-100 rounded-lg flex items-center justify-center mb-4">
              <Pill className="w-6 h-6 text-pink-600" />
            </div>
            <h3 className="text-gray-900 mb-1">Write Prescription</h3>
            <p className="text-gray-600 text-sm">Prescribe medications</p>
          </Link>
        </div>

        {/* Today's Schedule */}
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-gray-900">Today's Appointments</h2>
            <span className="text-sm text-gray-600">{todaysAppointments.length} appointments</span>
          </div>

          <div className="space-y-3">
            {todaysAppointments.map((apt) => (
              <div key={apt.id} className="p-4 bg-gray-50 rounded-lg border border-gray-200">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                      <Clock className="w-5 h-5 text-blue-600" />
                    </div>
                    <div>
                      <p className="text-gray-900">{apt.patient}</p>
                      <p className="text-gray-600 text-sm">NRIC: {apt.nric}</p>
                    </div>
                  </div>
                  <span
                    className={`px-2 py-1 text-xs rounded ${
                      apt.status === 'Checked-in'
                        ? 'bg-green-100 text-green-800'
                        : 'bg-blue-100 text-blue-800'
                    }`}
                  >
                    {apt.status}
                  </span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-600">{apt.time} • {apt.reason}</span>
                  <Link to={`/doctor/consultation/${apt.id}`} className="text-blue-600 hover:text-blue-700">
                    Start Consultation
                  </Link>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
