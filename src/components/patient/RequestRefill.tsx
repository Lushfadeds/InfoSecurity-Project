import { DashboardLayout } from '../layouts/DashboardLayout';
import { Calendar, FileText, Pill, CreditCard, Upload, User, Clock, ArrowLeft, AlertCircle, CheckCircle } from 'lucide-react';
import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

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

export function RequestRefill() {
  const [searchParams] = useSearchParams();
  const prescriptionId = searchParams.get('rx') || 'RX-2024-1122';
  const [deliveryMethod, setDeliveryMethod] = useState('pickup');
  const [deliveryAddress, setDeliveryAddress] = useState('');
  const [deliveryPostal, setDeliveryPostal] = useState('');
  const [deliveryUnit, setDeliveryUnit] = useState('');
  const [contactNumber, setContactNumber] = useState('');
  const [notes, setNotes] = useState('');
  const [showSuccess, setShowSuccess] = useState(false);

  // Mock prescription data
  const prescription = {
    id: prescriptionId,
    date: '2024-11-22',
    doctor: 'Dr. James Wong',
    medications: [
      { 
        name: 'Amlodipine 5mg', 
        dosage: '1 tablet', 
        frequency: 'Once daily', 
        duration: '30 days',
        refillsRemaining: 2,
        lastRefillDate: '2024-11-22'
      },
      { 
        name: 'Atorvastatin 20mg', 
        dosage: '1 tablet', 
        frequency: 'Once daily at night', 
        duration: '30 days',
        refillsRemaining: 2,
        lastRefillDate: '2024-11-22'
      },
    ],
    status: 'Active',
    validUntil: '2025-05-22',
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setShowSuccess(true);
  };

  if (showSuccess) {
    return (
      <DashboardLayout role="patient" sidebarItems={sidebarItems} userName="John Doe">
        <div className="max-w-2xl mx-auto">
          <div className="bg-white rounded-xl border border-gray-200 p-8 text-center">
            <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <CheckCircle className="w-10 h-10 text-green-600" />
            </div>
            <h1 className="text-gray-900 mb-2">Refill Request Submitted!</h1>
            <p className="text-gray-600 mb-6">
              Your prescription refill request has been submitted successfully. You will receive a notification once it's processed.
            </p>
            <div className="bg-gray-50 rounded-lg p-4 mb-6 text-left">
              <div className="flex justify-between mb-2">
                <span className="text-gray-600">Prescription ID</span>
                <span className="text-gray-900">{prescription.id}</span>
              </div>
              <div className="flex justify-between mb-2">
                <span className="text-gray-600">Delivery Method</span>
                <span className="text-gray-900">
                  {deliveryMethod === 'pickup' && 'Pick up at Clinic'}
                  {deliveryMethod === 'delivery' && 'Home Delivery'}
                </span>
              </div>
              <div className="flex justify-between mb-2">
                <span className="text-gray-600">Processing Time</span>
                <span className="text-gray-900">2-3 business days</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">Request ID</span>
                <span className="text-gray-900 text-sm">REF-{Date.now()}</span>
              </div>
            </div>
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6 text-left">
              <div className="flex items-start gap-2">
                <AlertCircle className="w-5 h-5 text-blue-600 mt-0.5" />
                <div>
                  <p className="text-sm text-blue-900 mb-1">Next Steps:</p>
                  <ul className="text-sm text-blue-800 space-y-1">
                    <li>• You will receive an SMS notification when your refill is ready</li>
                    <li>• {deliveryMethod === 'pickup' ? 'Pick up during clinic hours (9AM - 6PM)' : 'Delivery will arrive within 3-5 business days'}</li>
                    <li>• Payment can be made upon collection or delivery</li>
                  </ul>
                </div>
              </div>
            </div>
            <div className="flex gap-3 justify-center">
              <Link
                to="/patient/prescriptions"
                className="px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600"
              >
                Back to Prescriptions
              </Link>
              <Link
                to="/patient/dashboard"
                className="px-6 py-3 bg-white text-pink-600 border border-pink-300 rounded-lg hover:bg-pink-50"
              >
                Go to Dashboard
              </Link>
            </div>
          </div>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout role="patient" sidebarItems={sidebarItems} userName="John Doe">
      <div className="max-w-4xl mx-auto">
        {/* Back Button */}
        <Link
          to="/patient/prescriptions"
          className="flex items-center gap-2 text-pink-600 hover:text-pink-700 mb-6"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Prescriptions
        </Link>

        <h1 className="text-gray-900 mb-6">Request Prescription Refill</h1>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Refill Request Form */}
          <div className="lg:col-span-2">
            {/* Prescription Details */}
            <div className="bg-white rounded-xl border border-gray-200 p-6 mb-6">
              <h2 className="text-gray-900 mb-4">Prescription Details</h2>
              <div className="space-y-3">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Prescription ID</span>
                  <span className="text-gray-900">{prescription.id}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Prescribed by</span>
                  <span className="text-gray-900">{prescription.doctor}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Valid Until</span>
                  <span className="text-gray-900">{new Date(prescription.validUntil).toLocaleDateString('en-SG')}</span>
                </div>
              </div>

              <div className="mt-4 pt-4 border-t border-gray-200">
                <h3 className="text-gray-900 mb-3">Medications</h3>
                <div className="space-y-3">
                  {prescription.medications.map((med, index) => (
                    <div key={index} className="p-4 bg-gray-50 rounded-lg">
                      <div className="flex items-start justify-between mb-2">
                        <h4 className="text-gray-900">{med.name}</h4>
                        <span className="text-xs bg-green-100 text-green-800 px-2 py-1 rounded">
                          {med.refillsRemaining} refills left
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-3 text-sm">
                        <div>
                          <p className="text-gray-600 text-xs">Dosage</p>
                          <p className="text-gray-900">{med.dosage}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 text-xs">Frequency</p>
                          <p className="text-gray-900">{med.frequency}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Delivery Options */}
            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <h2 className="text-gray-900 mb-4">Delivery Options</h2>

              <form onSubmit={handleSubmit} className="space-y-6">
                {/* Delivery Method */}
                <div className="space-y-3">
                  <label className="flex items-start gap-3 p-4 border-2 rounded-lg cursor-pointer transition-all hover:bg-gray-50"
                    style={{ borderColor: deliveryMethod === 'pickup' ? '#ec4899' : '#e5e7eb' }}>
                    <input
                      type="radio"
                      name="delivery"
                      value="pickup"
                      checked={deliveryMethod === 'pickup'}
                      onChange={(e) => setDeliveryMethod(e.target.value)}
                      className="mt-1"
                    />
                    <div className="flex-1">
                      <p className="text-gray-900">Pick up at Clinic</p>
                      <p className="text-sm text-gray-600">Free - Ready in 2-3 business days</p>
                      <p className="text-xs text-gray-500 mt-1">123 Medical Center, Singapore 123456</p>
                    </div>
                  </label>

                  <label className="flex items-start gap-3 p-4 border-2 rounded-lg cursor-pointer transition-all hover:bg-gray-50"
                    style={{ borderColor: deliveryMethod === 'delivery' ? '#ec4899' : '#e5e7eb' }}>
                    <input
                      type="radio"
                      name="delivery"
                      value="delivery"
                      checked={deliveryMethod === 'delivery'}
                      onChange={(e) => setDeliveryMethod(e.target.value)}
                      className="mt-1"
                    />
                    <div className="flex-1">
                      <p className="text-gray-900">Home Delivery</p>
                      <p className="text-sm text-gray-600">$5.00 - Delivered in 3-5 business days</p>
                      <p className="text-xs text-gray-500 mt-1">Medication will be delivered to your registered address</p>
                    </div>
                  </label>
                </div>

                {/* Delivery Address (if delivery selected) */}
                {deliveryMethod === 'delivery' && (
                  <div className="space-y-4 pt-4 border-t border-gray-200">
                    <h3 className="text-gray-900">Delivery Address</h3>
                    <div>
                      <label className="block text-gray-700 mb-2">Street Address</label>
                      <input
                        type="text"
                        placeholder="123 Medical Road"
                        value={deliveryAddress}
                        onChange={(e) => setDeliveryAddress(e.target.value)}
                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                        required
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-gray-700 mb-2">Postal Code</label>
                        <input
                          type="text"
                          placeholder="123456"
                          value={deliveryPostal}
                          onChange={(e) => setDeliveryPostal(e.target.value)}
                          className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                          maxLength={6}
                          required
                        />
                      </div>
                      <div>
                        <label className="block text-gray-700 mb-2">Unit Number</label>
                        <input
                          type="text"
                          placeholder="#12-34"
                          value={deliveryUnit}
                          onChange={(e) => setDeliveryUnit(e.target.value)}
                          className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                        />
                      </div>
                    </div>
                  </div>
                )}

                {/* Contact Information */}
                <div className="pt-4 border-t border-gray-200">
                  <div>
                    <label className="block text-gray-700 mb-2">Contact Number</label>
                    <input
                      type="tel"
                      placeholder="+65 1234 5678"
                      value={contactNumber}
                      onChange={(e) => setContactNumber(e.target.value)}
                      className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                      required
                    />
                    <p className="text-xs text-gray-500 mt-1">We'll contact you when your refill is ready</p>
                  </div>
                </div>

                {/* Additional Notes */}
                <div>
                  <label className="block text-gray-700 mb-2">Additional Notes (Optional)</label>
                  <textarea
                    placeholder="Any special instructions or requests..."
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500 min-h-[100px]"
                  />
                </div>

                {/* Important Notice */}
                <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                  <div className="flex items-start gap-2">
                    <AlertCircle className="w-5 h-5 text-orange-600 mt-0.5" />
                    <div>
                      <p className="text-sm text-orange-900">Important:</p>
                      <ul className="text-sm text-orange-800 space-y-1 mt-1">
                        <li>• Refill requests require pharmacist approval</li>
                        <li>• Doctor consultation may be required if prescription has expired</li>
                        <li>• Payment will be processed upon collection or delivery</li>
                      </ul>
                    </div>
                  </div>
                </div>

                <button
                  type="submit"
                  className="w-full px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600"
                >
                  Submit Refill Request
                </button>
              </form>
            </div>
          </div>

          {/* Summary Sidebar */}
          <div className="lg:col-span-1">
            <div className="bg-white rounded-xl border border-gray-200 p-6 sticky top-6">
              <h3 className="text-gray-900 mb-4">Refill Summary</h3>
              <div className="space-y-3 mb-4">
                <div>
                  <p className="text-xs text-gray-600 mb-1">Medications</p>
                  <ul className="text-sm text-gray-900 space-y-1">
                    {prescription.medications.map((med, index) => (
                      <li key={index}>• {med.name}</li>
                    ))}
                  </ul>
                </div>
                <div className="pt-3 border-t border-gray-200">
                  <p className="text-xs text-gray-600 mb-1">Estimated Cost</p>
                  <p className="text-gray-900">$45.00 - $65.00</p>
                  <p className="text-xs text-gray-500 mt-1">Final cost will be confirmed by pharmacist</p>
                </div>
                {deliveryMethod === 'delivery' && (
                  <div className="pt-3 border-t border-gray-200">
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-600">Delivery Fee</span>
                      <span className="text-gray-900">$5.00</span>
                    </div>
                  </div>
                )}
              </div>

              <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 text-sm">
                <p className="text-blue-900 mb-1">Processing Time</p>
                <p className="text-blue-800">2-3 business days</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
