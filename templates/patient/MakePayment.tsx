import { DashboardLayout } from '../layouts/DashboardLayout';
import { Calendar, FileText, Pill, CreditCard, Upload, User, Clock, Lock, CheckCircle, AlertCircle, ArrowLeft } from 'lucide-react';
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

export function MakePayment() {
  const [searchParams] = useSearchParams();
  const invoiceId = searchParams.get('invoice') || 'INV-2024-1234';
  const [paymentMethod, setPaymentMethod] = useState('card');
  const [cardNumber, setCardNumber] = useState('');
  const [expiryDate, setExpiryDate] = useState('');
  const [cvv, setCvv] = useState('');
  const [cardholderName, setCardholderName] = useState('');
  const [saveCard, setSaveCard] = useState(false);
  const [showSuccess, setShowSuccess] = useState(false);

  // Mock invoice data
  const invoice = {
    id: invoiceId,
    date: '2024-12-10',
    description: 'General Consultation',
    items: [
      { name: 'Consultation Fee', amount: 50.00 },
      { name: 'Medications', amount: 35.00 },
      { name: 'Medical Certificate', amount: 15.00 },
    ],
    subtotal: 100.00,
    gst: 9.00,
    total: 109.00,
  };

  const handlePayment = (e: React.FormEvent) => {
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
            <h1 className="text-gray-900 mb-2">Payment Successful!</h1>
            <p className="text-gray-600 mb-6">
              Your payment has been processed successfully.
            </p>
            <div className="bg-gray-50 rounded-lg p-4 mb-6 text-left">
              <div className="flex justify-between mb-2">
                <span className="text-gray-600">Invoice</span>
                <span className="text-gray-900">{invoice.id}</span>
              </div>
              <div className="flex justify-between mb-2">
                <span className="text-gray-600">Amount Paid</span>
                <span className="text-gray-900">${invoice.total.toFixed(2)}</span>
              </div>
              <div className="flex justify-between mb-2">
                <span className="text-gray-600">Payment Method</span>
                <span className="text-gray-900">
                  {paymentMethod === 'card' && 'Credit/Debit Card'}
                  {paymentMethod === 'paynow' && 'PayNow'}
                  {paymentMethod === 'giro' && 'GIRO'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">Transaction ID</span>
                <span className="text-gray-900 text-sm">TXN-{Date.now()}</span>
              </div>
            </div>
            <div className="flex gap-3 justify-center">
              <Link
                to="/patient/billing"
                className="px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600"
              >
                Back to Billing
              </Link>
              <button className="px-6 py-3 bg-white text-pink-600 border border-pink-300 rounded-lg hover:bg-pink-50">
                Download Receipt
              </button>
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
          to="/patient/billing"
          className="flex items-center gap-2 text-pink-600 hover:text-pink-700 mb-6"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Billing
        </Link>

        <h1 className="text-gray-900 mb-6">Make Payment</h1>

        <div className="grid lg:grid-cols-3 gap-6">
          {/* Payment Form */}
          <div className="lg:col-span-2">
            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <h2 className="text-gray-900 mb-4">Payment Method</h2>

              {/* Payment Method Selector */}
              <div className="grid grid-cols-3 gap-3 mb-6">
                <button
                  onClick={() => setPaymentMethod('card')}
                  className={`p-4 border-2 rounded-lg transition-all ${
                    paymentMethod === 'card'
                      ? 'border-pink-500 bg-pink-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                >
                  <CreditCard className={`w-6 h-6 mx-auto mb-2 ${
                    paymentMethod === 'card' ? 'text-pink-600' : 'text-gray-600'
                  }`} />
                  <p className="text-sm text-gray-900">Card</p>
                </button>
                <button
                  onClick={() => setPaymentMethod('paynow')}
                  className={`p-4 border-2 rounded-lg transition-all ${
                    paymentMethod === 'paynow'
                      ? 'border-pink-500 bg-pink-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                >
                  <div className={`w-6 h-6 mx-auto mb-2 rounded ${
                    paymentMethod === 'paynow' ? 'bg-pink-600' : 'bg-gray-600'
                  }`}></div>
                  <p className="text-sm text-gray-900">PayNow</p>
                </button>
                <button
                  onClick={() => setPaymentMethod('giro')}
                  className={`p-4 border-2 rounded-lg transition-all ${
                    paymentMethod === 'giro'
                      ? 'border-pink-500 bg-pink-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                >
                  <div className={`w-6 h-6 mx-auto mb-2 rounded ${
                    paymentMethod === 'giro' ? 'bg-pink-600' : 'bg-gray-600'
                  }`}></div>
                  <p className="text-sm text-gray-900">GIRO</p>
                </button>
              </div>

              {/* Card Payment Form */}
              {paymentMethod === 'card' && (
                <form onSubmit={handlePayment} className="space-y-4">
                  <div>
                    <label className="block text-gray-700 mb-2">Card Number</label>
                    <input
                      type="text"
                      placeholder="1234 5678 9012 3456"
                      value={cardNumber}
                      onChange={(e) => setCardNumber(e.target.value)}
                      className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                      maxLength={19}
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-gray-700 mb-2">Cardholder Name</label>
                    <input
                      type="text"
                      placeholder="JOHN DOE"
                      value={cardholderName}
                      onChange={(e) => setCardholderName(e.target.value)}
                      className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                      required
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-gray-700 mb-2">Expiry Date</label>
                      <input
                        type="text"
                        placeholder="MM/YY"
                        value={expiryDate}
                        onChange={(e) => setExpiryDate(e.target.value)}
                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                        maxLength={5}
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-gray-700 mb-2">CVV</label>
                      <input
                        type="password"
                        placeholder="123"
                        value={cvv}
                        onChange={(e) => setCvv(e.target.value)}
                        className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
                        maxLength={4}
                        required
                      />
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id="saveCard"
                      checked={saveCard}
                      onChange={(e) => setSaveCard(e.target.checked)}
                      className="w-4 h-4 text-pink-600 rounded focus:ring-pink-500"
                    />
                    <label htmlFor="saveCard" className="text-gray-700 text-sm">
                      Save card for future payments
                    </label>
                  </div>
                  <button
                    type="submit"
                    className="w-full px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 flex items-center justify-center gap-2"
                  >
                    <Lock className="w-4 h-4" />
                    Pay ${invoice.total.toFixed(2)}
                  </button>
                </form>
              )}

              {/* PayNow */}
              {paymentMethod === 'paynow' && (
                <div className="space-y-4">
                  <div className="bg-gray-50 rounded-lg p-6 text-center">
                    <div className="w-48 h-48 bg-white border-2 border-gray-300 rounded-lg mx-auto mb-4 flex items-center justify-center">
                      <p className="text-gray-400">QR Code</p>
                    </div>
                    <p className="text-gray-700 mb-2">Scan QR code with your banking app</p>
                    <p className="text-gray-600 text-sm">or enter UEN: 202012345A</p>
                  </div>
                  <button
                    onClick={handlePayment}
                    className="w-full px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600"
                  >
                    Confirm Payment
                  </button>
                </div>
              )}

              {/* GIRO */}
              {paymentMethod === 'giro' && (
                <div className="space-y-4">
                  <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                    <p className="text-sm text-blue-800">
                      GIRO payment will be deducted from your linked bank account within 3 working days.
                    </p>
                  </div>
                  <div>
                    <label className="block text-gray-700 mb-2">Linked Bank Account</label>
                    <select className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500">
                      <option>DBS - ****1234</option>
                      <option>OCBC - ****5678</option>
                      <option>UOB - ****9012</option>
                    </select>
                  </div>
                  <button
                    onClick={handlePayment}
                    className="w-full px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600"
                  >
                    Authorize GIRO Payment
                  </button>
                </div>
              )}

              {/* Security Notice */}
              <div className="mt-6 flex items-start gap-2 text-sm text-gray-600 bg-green-50 border border-green-200 rounded-lg p-3">
                <Lock className="w-4 h-4 text-green-600 mt-0.5" />
                <p>
                  Your payment is secured with 256-bit SSL encryption. We do not store your full card details.
                </p>
              </div>
            </div>
          </div>

          {/* Invoice Summary */}
          <div className="lg:col-span-1">
            <div className="bg-white rounded-xl border border-gray-200 p-6 sticky top-6">
              <h3 className="text-gray-900 mb-4">Payment Summary</h3>
              <div className="space-y-3 mb-4">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Invoice</span>
                  <span className="text-gray-900">{invoice.id}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Date</span>
                  <span className="text-gray-900">{new Date(invoice.date).toLocaleDateString('en-SG')}</span>
                </div>
              </div>
              <div className="border-t border-gray-200 pt-3 mb-3 space-y-2">
                {invoice.items.map((item, index) => (
                  <div key={index} className="flex justify-between text-sm">
                    <span className="text-gray-600">{item.name}</span>
                    <span className="text-gray-900">${item.amount.toFixed(2)}</span>
                  </div>
                ))}
              </div>
              <div className="border-t border-gray-200 pt-3 space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Subtotal</span>
                  <span className="text-gray-900">${invoice.subtotal.toFixed(2)}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">GST (9%)</span>
                  <span className="text-gray-900">${invoice.gst.toFixed(2)}</span>
                </div>
              </div>
              <div className="border-t-2 border-gray-300 mt-4 pt-4 flex justify-between">
                <span className="text-gray-900">Total Amount</span>
                <span className="text-2xl text-gray-900">${invoice.total.toFixed(2)}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
