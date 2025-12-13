import { DashboardLayout } from '../layouts/DashboardLayout';
import { Users, Calendar, CreditCard, Upload, Plus } from 'lucide-react';

const sidebarItems = [
  { icon: <Users className="w-5 h-5" />, label: 'Dashboard', path: '/staff/dashboard' },
  { icon: <Calendar className="w-5 h-5" />, label: 'Create Appointment', path: '/staff/create-appointment' },
  { icon: <CreditCard className="w-5 h-5" />, label: 'Billing & Invoicing', path: '/staff/billing' },
  { icon: <Upload className="w-5 h-5" />, label: 'Upload Documents', path: '/staff/upload' },
];

export function StaffBilling() {
  const items = [{ name: 'Consultation Fee', amount: 50.00 }];

  return (
    <DashboardLayout role="staff" sidebarItems={sidebarItems} userName="Alice Wong">
      <div className="max-w-4xl">
        <h1 className="text-gray-900 mb-6">Billing & Invoice Processing</h1>

        <div className="bg-white rounded-xl border border-gray-200 p-6 mb-6">
          <h2 className="text-gray-900 mb-4">Patient Information</h2>
          <input type="text" placeholder="Search patient..." className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500" />
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-gray-900 mb-4">Invoice Items</h2>
          <div className="space-y-3">
            {items.map((item, i) => (
              <div key={i} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <span>{item.name}</span>
                <span>${item.amount.toFixed(2)}</span>
              </div>
            ))}
            <button className="flex items-center gap-2 text-purple-600 hover:bg-purple-50 px-4 py-2 rounded-lg">
              <Plus className="w-4 h-4" />
              Add Item
            </button>
          </div>
          <div className="mt-4 pt-4 border-t border-gray-200 flex justify-between">
            <span>Total</span>
            <span className="text-2xl">$50.00</span>
          </div>
          <button className="w-full mt-6 px-6 py-3 bg-purple-500 text-white rounded-lg hover:bg-purple-600">
            Generate Invoice
          </button>
        </div>
      </div>
    </DashboardLayout>
  );
}
