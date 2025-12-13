import { DashboardLayout } from '../layouts/DashboardLayout';
import { Calendar, FileText, Pill, CreditCard, Upload, User, Clock, Download, X } from 'lucide-react';
import { useState } from 'react';

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

const appointments = [
  {
    id: '1',
    date: '2025-01-15',
    time: '10:00 AM',
    doctor: 'Dr. Sarah Tan',
    specialty: 'General Practitioner',
    status: 'Confirmed',
    notes: null,
    documents: [],
  },
  {
    id: '2',
    date: '2024-12-10',
    time: '3:00 PM',
    doctor: 'Dr. Sarah Tan',
    specialty: 'General Practitioner',
    status: 'Completed',
    notes: 'Consultation completed. Prescribed antibiotics for throat infection.',
    documents: ['MC-2024-1210.pdf', 'Prescription-2024-1210.pdf'],
  },
  {
    id: '3',
    date: '2024-11-22',
    time: '11:30 AM',
    doctor: 'Dr. James Wong',
    specialty: 'Cardiologist',
    status: 'Completed',
    notes: 'Regular checkup. Blood pressure normal. Continue current medication.',
    documents: ['Lab-Results-2024-1122.pdf'],
  },
  {
    id: '4',
    date: '2024-10-15',
    time: '2:00 PM',
    doctor: 'Dr. Michelle Lee',
    specialty: 'Dermatologist',
    status: 'Completed',
    notes: 'Treated skin condition. Follow-up in 3 months if symptoms persist.',
    documents: [],
  },
];

export function AppointmentHistory() {
  const [selectedAppointment, setSelectedAppointment] = useState<string | null>(null);

  const appointment = appointments.find(a => a.id === selectedAppointment);

  return (
    <DashboardLayout role="patient" sidebarItems={sidebarItems} userName="John Doe">
      <div className="max-w-5xl">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-gray-900">Appointment History</h1>
          <a
            href="/patient/book-appointment"
            className="px-4 py-2 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
          >
            Book New Appointment
          </a>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="px-6 py-3 text-left text-gray-700">Date & Time</th>
                <th className="px-6 py-3 text-left text-gray-700">Doctor</th>
                <th className="px-6 py-3 text-left text-gray-700">Status</th>
                <th className="px-6 py-3 text-left text-gray-700">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {appointments.map((apt) => (
                <tr key={apt.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <div>
                      <p className="text-gray-900">
                        {new Date(apt.date).toLocaleDateString('en-SG', {
                          month: 'short',
                          day: 'numeric',
                          year: 'numeric',
                        })}
                      </p>
                      <p className="text-gray-600 text-sm">{apt.time}</p>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div>
                      <p className="text-gray-900">{apt.doctor}</p>
                      <p className="text-gray-600 text-sm">{apt.specialty}</p>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span
                      className={`px-2 py-1 text-xs rounded ${
                        apt.status === 'Confirmed'
                          ? 'bg-green-100 text-green-800'
                          : 'bg-gray-100 text-gray-800'
                      }`}
                    >
                      {apt.status}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <button
                      onClick={() => setSelectedAppointment(apt.id)}
                      className="text-pink-600 hover:text-pink-700 text-sm"
                    >
                      View Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Details Modal */}
        {selectedAppointment && appointment && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
              <div className="p-6 border-b border-gray-200 flex items-center justify-between">
                <h2 className="text-gray-900">Appointment Details</h2>
                <button
                  onClick={() => setSelectedAppointment(null)}
                  className="p-2 hover:bg-gray-100 rounded-lg"
                >
                  <X className="w-5 h-5 text-gray-500" />
                </button>
              </div>

              <div className="p-6 space-y-6">
                <div className="grid sm:grid-cols-2 gap-4">
                  <div>
                    <p className="text-gray-600 text-sm mb-1">Date</p>
                    <p className="text-gray-900">
                      {new Date(appointment.date).toLocaleDateString('en-SG', {
                        weekday: 'long',
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric',
                      })}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-600 text-sm mb-1">Time</p>
                    <p className="text-gray-900">{appointment.time}</p>
                  </div>
                  <div>
                    <p className="text-gray-600 text-sm mb-1">Doctor</p>
                    <p className="text-gray-900">{appointment.doctor}</p>
                  </div>
                  <div>
                    <p className="text-gray-600 text-sm mb-1">Specialty</p>
                    <p className="text-gray-900">{appointment.specialty}</p>
                  </div>
                </div>

                {appointment.notes && (
                  <div>
                    <p className="text-gray-600 text-sm mb-2">Consultation Notes</p>
                    <div className="p-4 bg-gray-50 rounded-lg border border-gray-200">
                      <p className="text-gray-800">{appointment.notes}</p>
                      <p className="text-gray-500 text-xs mt-2">
                        🔒 Encrypted and access-controlled
                      </p>
                    </div>
                  </div>
                )}

                {appointment.documents.length > 0 && (
                  <div>
                    <p className="text-gray-600 text-sm mb-2">Related Documents</p>
                    <div className="space-y-2">
                      {appointment.documents.map((doc, index) => (
                        <div
                          key={index}
                          className="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100"
                        >
                          <div className="flex items-center gap-3">
                            <FileText className="w-5 h-5 text-pink-600" />
                            <span className="text-gray-900 text-sm">{doc}</span>
                          </div>
                          <button className="text-pink-600 hover:text-pink-700">
                            <Download className="w-4 h-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
