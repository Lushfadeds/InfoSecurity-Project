import { DashboardLayout } from '../layouts/DashboardLayout';
import { Calendar, FileText, Pill, CreditCard, Upload, User, Clock, Search, CheckCircle } from 'lucide-react';
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

const doctors = [
  { id: '1', name: 'Dr. Sarah Tan', specialty: 'General Practitioner', photo: 'ST' },
  { id: '2', name: 'Dr. James Wong', specialty: 'Cardiologist', photo: 'JW' },
  { id: '3', name: 'Dr. Michelle Lee', specialty: 'Dermatologist', photo: 'ML' },
  { id: '4', name: 'Dr. David Lim', specialty: 'Pediatrician', photo: 'DL' },
];

const timeSlots = [
  '09:00 AM', '09:30 AM', '10:00 AM', '10:30 AM', '11:00 AM', '11:30 AM',
  '02:00 PM', '02:30 PM', '03:00 PM', '03:30 PM', '04:00 PM', '04:30 PM',
];

export function BookAppointment() {
  const [step, setStep] = useState(1);
  const [selectedDoctor, setSelectedDoctor] = useState<string | null>(null);
  const [selectedDate, setSelectedDate] = useState('');
  const [selectedTime, setSelectedTime] = useState('');
  const [reason, setReason] = useState('');
  const [showConfirmation, setShowConfirmation] = useState(false);

  const handleBooking = () => {
    setShowConfirmation(true);
  };

  const doctor = doctors.find(d => d.id === selectedDoctor);

  return (
    <DashboardLayout role="patient" sidebarItems={sidebarItems} userName="John Doe">
      <div className="max-w-4xl">
        <h1 className="text-gray-900 mb-6">Book an Appointment</h1>

        {!showConfirmation ? (
          <>
            {/* Progress Steps */}
            <div className="flex items-center justify-center mb-8">
              <div className="flex items-center gap-2">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                  step >= 1 ? 'bg-pink-500 text-white' : 'bg-gray-200 text-gray-500'
                }`}>1</div>
                <span className="text-sm text-gray-600">Select Doctor</span>
              </div>
              <div className={`w-16 h-0.5 mx-2 ${step >= 2 ? 'bg-pink-500' : 'bg-gray-200'}`}></div>
              <div className="flex items-center gap-2">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                  step >= 2 ? 'bg-pink-500 text-white' : 'bg-gray-200 text-gray-500'
                }`}>2</div>
                <span className="text-sm text-gray-600">Date & Time</span>
              </div>
              <div className={`w-16 h-0.5 mx-2 ${step >= 3 ? 'bg-pink-500' : 'bg-gray-200'}`}></div>
              <div className="flex items-center gap-2">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                  step >= 3 ? 'bg-pink-500 text-white' : 'bg-gray-200 text-gray-500'
                }`}>3</div>
                <span className="text-sm text-gray-600">Confirm</span>
              </div>
            </div>

            {/* Step 1: Select Doctor */}
            {step === 1 && (
              <div className="space-y-4">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search by name or specialty..."
                    className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                  />
                </div>

                <div className="grid sm:grid-cols-2 gap-4">
                  {doctors.map((doc) => (
                    <div
                      key={doc.id}
                      onClick={() => setSelectedDoctor(doc.id)}
                      className={`p-4 border-2 rounded-xl cursor-pointer transition-all ${
                        selectedDoctor === doc.id
                          ? 'border-pink-500 bg-pink-50'
                          : 'border-gray-200 hover:border-gray-300'
                      }`}
                    >
                      <div className="flex items-center gap-4">
                        <div className="w-16 h-16 bg-gradient-to-br from-pink-200 to-pink-300 rounded-full flex items-center justify-center text-white">
                          {doc.photo}
                        </div>
                        <div>
                          <h3 className="text-gray-900">{doc.name}</h3>
                          <p className="text-gray-600 text-sm">{doc.specialty}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                <button
                  onClick={() => setStep(2)}
                  disabled={!selectedDoctor}
                  className="w-full px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors disabled:bg-gray-300 disabled:cursor-not-allowed"
                >
                  Continue
                </button>
              </div>
            )}

            {/* Step 2: Select Date & Time */}
            {step === 2 && (
              <div className="space-y-6">
                <div>
                  <label className="block text-gray-700 mb-2">Select Date</label>
                  <input
                    type="date"
                    value={selectedDate}
                    onChange={(e) => setSelectedDate(e.target.value)}
                    min={new Date().toISOString().split('T')[0]}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                  />
                </div>

                <div>
                  <label className="block text-gray-700 mb-2">Available Time Slots</label>
                  <div className="grid grid-cols-3 sm:grid-cols-4 gap-3">
                    {timeSlots.map((time) => (
                      <button
                        key={time}
                        onClick={() => setSelectedTime(time)}
                        className={`px-4 py-2 rounded-lg border-2 transition-all ${
                          selectedTime === time
                            ? 'border-pink-500 bg-pink-50 text-pink-700'
                            : 'border-gray-200 hover:border-gray-300'
                        }`}
                      >
                        {time}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="flex gap-3">
                  <button
                    onClick={() => setStep(1)}
                    className="flex-1 px-6 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors"
                  >
                    Back
                  </button>
                  <button
                    onClick={() => setStep(3)}
                    disabled={!selectedDate || !selectedTime}
                    className="flex-1 px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors disabled:bg-gray-300 disabled:cursor-not-allowed"
                  >
                    Continue
                  </button>
                </div>
              </div>
            )}

            {/* Step 3: Confirm Details */}
            {step === 3 && (
              <div className="space-y-6">
                <div className="bg-gray-50 border border-gray-200 rounded-xl p-6 space-y-4">
                  <div>
                    <p className="text-gray-600 text-sm mb-1">Doctor</p>
                    <p className="text-gray-900">{doctor?.name} - {doctor?.specialty}</p>
                  </div>
                  <div>
                    <p className="text-gray-600 text-sm mb-1">Date & Time</p>
                    <p className="text-gray-900">
                      {new Date(selectedDate).toLocaleDateString('en-SG', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })} at {selectedTime}
                    </p>
                  </div>
                </div>

                <div>
                  <label className="block text-gray-700 mb-2">Reason for Visit (Optional)</label>
                  <textarea
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    rows={4}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                    placeholder="Briefly describe your symptoms or reason for visit..."
                  />
                </div>

                <div className="flex gap-3">
                  <button
                    onClick={() => setStep(2)}
                    className="flex-1 px-6 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors"
                  >
                    Back
                  </button>
                  <button
                    onClick={handleBooking}
                    className="flex-1 px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
                  >
                    Confirm Booking
                  </button>
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="text-center py-12">
            <div className="w-20 h-20 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-6">
              <CheckCircle className="w-10 h-10 text-green-600" />
            </div>
            <h2 className="text-gray-900 mb-4">Appointment Confirmed!</h2>
            <p className="text-gray-600 mb-6">
              Your appointment with {doctor?.name} on {new Date(selectedDate).toLocaleDateString('en-SG')} at {selectedTime} has been confirmed.
            </p>
            <p className="text-gray-600 mb-8">
              You will receive a confirmation email and SMS shortly.
            </p>
            <div className="flex gap-4 justify-center">
              <a
                href="/patient/dashboard"
                className="px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
              >
                Back to Dashboard
              </a>
              <a
                href="/patient/appointments"
                className="px-6 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors"
              >
                View Appointments
              </a>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
