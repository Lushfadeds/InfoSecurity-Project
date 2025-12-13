import { DashboardLayout } from '../layouts/DashboardLayout';
import { Calendar, FileText, Pill, CreditCard, Upload, User, Clock, Download, CheckCircle, AlertCircle } from 'lucide-react';
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

const invoices = [
  {
    id: 'INV-2024-1234',
    date: '2024-12-10',
    description: 'General Consultation',
    items: [
      { name: 'Consultation Fee', amount: 50.00 },
      { name: 'Medications', amount: 35.00 },
      { name: 'Medical Certificate', amount: 15.00 },
    ],
    total: 100.00,
    status: 'Pending',
  },
  {
    id: 'INV-2024-1122',
    date: '2024-11-22',
    description: 'Cardiology Consultation',
    items: [
      { name: 'Specialist Consultation', amount: 120.00 },
      { name: 'ECG Test', amount: 80.00 },
      { name: 'Medications', amount: 65.00 },
    ],
    total: 265.00,
    status: 'Paid',
    paidDate: '2024-11-22',
  },
  {
    id: 'INV-2024-0915',
    date: '2024-09-15',
    description: 'General Consultation',
    items: [
      { name: 'Consultation Fee', amount: 50.00 },
      { name: 'Medications', amount: 28.00 },
    ],
    total: 78.00,
    status: 'Paid',
    paidDate: '2024-09-15',
  },
];

export function BillingPayment() {
  return (
    <DashboardLayout role="patient" sidebarItems={sidebarItems} userName="John Doe">
      <div className="max-w-5xl">
        <h1 className="text-gray-900 mb-6">Billing & Payment History</h1>

        <div className="grid gap-4">
          {invoices.map((invoice) => (
            <div key={invoice.id} className="bg-white rounded-xl border border-gray-200 p-6">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <h3 className="text-gray-900">{invoice.id}</h3>
                    {invoice.status === 'Paid' ? (
                      <span className="px-2 py-1 bg-green-100 text-green-800 text-xs rounded flex items-center gap-1">
                        <CheckCircle className="w-3 h-3" />
                        Paid
                      </span>
                    ) : (
                      <span className="px-2 py-1 bg-orange-100 text-orange-800 text-xs rounded flex items-center gap-1">
                        <AlertCircle className="w-3 h-3" />
                        Pending
                      </span>
                    )}
                  </div>
                  <p className="text-gray-600 text-sm">{invoice.description}</p>
                  <p className="text-gray-500 text-xs">
                    Date: {new Date(invoice.date).toLocaleDateString('en-SG')}
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-gray-600 text-sm mb-1">Total Amount</p>
                  <p className="text-2xl text-gray-900">${invoice.total.toFixed(2)}</p>
                </div>
              </div>

              <div className="border-t border-gray-200 pt-4 space-y-2">
                {invoice.items.map((item, index) => (
                  <div key={index} className="flex justify-between text-sm">
                    <span className="text-gray-600">{item.name}</span>
                    <span className="text-gray-900">${item.amount.toFixed(2)}</span>
                  </div>
                ))}
              </div>

              <div className="border-t border-gray-200 mt-4 pt-4 flex items-center justify-between">
                {invoice.status === 'Paid' ? (
                  <span className="text-sm text-gray-600">
                    Paid on {new Date(invoice.paidDate!).toLocaleDateString('en-SG')}
                  </span>
                ) : (
                  <Link
                    to={`/patient/make-payment?invoice=${invoice.id}`}
                    className="px-4 py-2 bg-pink-500 text-white rounded-lg hover:bg-pink-600 text-sm"
                  >
                    Make Payment
                  </Link>
                )}
                <button className="flex items-center gap-2 text-pink-600 hover:text-pink-700 text-sm">
                  <Download className="w-4 h-4" />
                  Download Receipt
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </DashboardLayout>
  );
}