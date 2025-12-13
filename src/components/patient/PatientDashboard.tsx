import { DashboardLayout } from '../layouts/DashboardLayout';
import { Calendar, FileText, Pill, CreditCard, Upload, User, AlertCircle, Clock } from 'lucide-react';
import { Link } from 'react-router-dom';

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

export function PatientDashboard() {
  const upcomingAppointments = [
    {
      id: '1',
      date: '2025-01-15',
      time: '10:00 AM',
      doctor: 'Dr. Sarah Tan',
      specialty: 'General Practitioner',
      status: 'Confirmed',
    },
    {
      id: '2',
      date: '2025-01-22',
      time: '2:30 PM',
      doctor: 'Dr. James Wong',
      specialty: 'Cardiologist',
      status: 'Confirmed',
    },
  ];

  const recentDocuments = [
    { type: 'Medical Certificate', date: '2024-12-10', doctor: 'Dr. Sarah Tan' },
    { type: 'Prescription', date: '2024-12-10', doctor: 'Dr. Sarah Tan' },
    { type: 'Lab Results', date: '2024-12-05', doctor: 'Dr. James Wong' },
  ];

  const pendingActions = [
    { message: 'Complete payment for Invoice #INV-2024-1234', link: '/patient/billing' },
    { message: 'New lab results available for review', link: '/patient/upload' },
  ];

  return (
    <DashboardLayout role="patient" sidebarItems={sidebarItems} userName="John Doe">
      <div className="max-w-7xl">
        {/* Welcome Section */}
        <div className="mb-8">
          <h1 className="text-gray-900 mb-2">Welcome back, John</h1>
          <p className="text-gray-600">
            NRIC: S****123A (masked for security)
          </p>
        </div>

        {/* Alerts */}
        {pendingActions.length > 0 && (
          <div className="mb-6 space-y-3">
            {pendingActions.map((action, index) => (
              <div
                key={index}
                className="flex items-start gap-3 p-4 bg-pink-50 border border-pink-200 rounded-lg"
              >
                <AlertCircle className="w-5 h-5 text-pink-600 flex-shrink-0 mt-0.5" />
                <div className="flex-1">
                  <p className="text-gray-800">{action.message}</p>
                </div>
                <Link
                  to={action.link}
                  className="text-pink-600 hover:text-pink-700 flex-shrink-0"
                >
                  View →
                </Link>
              </div>
            ))}
          </div>
        )}

        {/* Quick Actions */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <Link
            to="/patient/book-appointment"
            className="bg-white p-6 rounded-xl border border-gray-200 hover:shadow-lg hover:border-pink-300 transition-all"
          >
            <div className="w-12 h-12 bg-pink-100 rounded-lg flex items-center justify-center mb-4">
              <Calendar className="w-6 h-6 text-pink-600" />
            </div>
            <h3 className="text-gray-900 mb-1">Book Appointment</h3>
            <p className="text-gray-600 text-sm">Schedule a visit with your doctor</p>
          </Link>

          <Link
            to="/patient/medical-certificates"
            className="bg-white p-6 rounded-xl border border-gray-200 hover:shadow-lg hover:border-pink-300 transition-all"
          >
            <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-4">
              <FileText className="w-6 h-6 text-blue-600" />
            </div>
            <h3 className="text-gray-900 mb-1">Medical Certificates</h3>
            <p className="text-gray-600 text-sm">View and download your MCs</p>
          </Link>

          <Link
            to="/patient/prescriptions"
            className="bg-white p-6 rounded-xl border border-gray-200 hover:shadow-lg hover:border-pink-300 transition-all"
          >
            <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mb-4">
              <Pill className="w-6 h-6 text-green-600" />
            </div>
            <h3 className="text-gray-900 mb-1">Prescriptions</h3>
            <p className="text-gray-600 text-sm">Access your medications</p>
          </Link>

          <Link
            to="/patient/billing"
            className="bg-white p-6 rounded-xl border border-gray-200 hover:shadow-lg hover:border-pink-300 transition-all"
          >
            <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mb-4">
              <CreditCard className="w-6 h-6 text-purple-600" />
            </div>
            <h3 className="text-gray-900 mb-1">Bills & Payment</h3>
            <p className="text-gray-600 text-sm">View invoices and receipts</p>
          </Link>
        </div>

        <div className="grid lg:grid-cols-2 gap-6">
          {/* Upcoming Appointments */}
          <div className="bg-white rounded-xl border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-gray-900">Upcoming Appointments</h2>
              <Link to="/patient/appointments" className="text-pink-600 hover:text-pink-700 text-sm">
                View All
              </Link>
            </div>

            {upcomingAppointments.length > 0 ? (
              <div className="space-y-4">
                {upcomingAppointments.map((apt) => (
                  <div
                    key={apt.id}
                    className="p-4 bg-gray-50 rounded-lg border border-gray-200"
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <p className="text-gray-900">{apt.doctor}</p>
                        <p className="text-gray-600 text-sm">{apt.specialty}</p>
                      </div>
                      <span className="px-2 py-1 bg-green-100 text-green-800 text-xs rounded">
                        {apt.status}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-sm text-gray-600">
                      <span className="flex items-center gap-1">
                        <Calendar className="w-4 h-4" />
                        {new Date(apt.date).toLocaleDateString('en-SG', {
                          month: 'short',
                          day: 'numeric',
                          year: 'numeric',
                        })}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="w-4 h-4" />
                        {apt.time}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 text-center py-8">No upcoming appointments</p>
            )}
          </div>

          {/* Recent Documents */}
          <div className="bg-white rounded-xl border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-gray-900">Recent Documents</h2>
              <Link to="/patient/medical-certificates" className="text-pink-600 hover:text-pink-700 text-sm">
                View All
              </Link>
            </div>

            <div className="space-y-3">
              {recentDocuments.map((doc, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-pink-100 rounded-lg flex items-center justify-center">
                      <FileText className="w-5 h-5 text-pink-600" />
                    </div>
                    <div>
                      <p className="text-gray-900 text-sm">{doc.type}</p>
                      <p className="text-gray-600 text-xs">
                        {new Date(doc.date).toLocaleDateString('en-SG')}
                      </p>
                    </div>
                  </div>
                  <button className="text-pink-600 hover:text-pink-700 text-sm">
                    Download
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
