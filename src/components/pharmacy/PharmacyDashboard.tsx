import { Package, AlertTriangle, Clock, CheckCircle } from 'lucide-react';
import { DashboardLayout } from '../layouts/DashboardLayout';

export function PharmacyDashboard() {
  const stats = [
    { label: 'Pending Prescriptions', value: '12', icon: Clock, color: 'text-orange-600', bg: 'bg-orange-50' },
    { label: 'Dispensed Today', value: '34', icon: CheckCircle, color: 'text-green-600', bg: 'bg-green-50' },
    { label: 'Low Stock Items', value: '8', icon: AlertTriangle, color: 'text-red-600', bg: 'bg-red-50' },
    { label: 'Total Inventory', value: '456', icon: Package, color: 'text-blue-600', bg: 'bg-blue-50' },
  ];

  const pendingPrescriptions = [
    { id: 'RX001', patient: 'Sarah Lee', doctor: 'Dr. Chen', time: '10:30 AM', items: 3, priority: 'Normal' },
    { id: 'RX002', patient: 'James Tan', doctor: 'Dr. Lim', time: '10:45 AM', items: 2, priority: 'Urgent' },
    { id: 'RX003', patient: 'Mary Wong', doctor: 'Dr. Kumar', time: '11:00 AM', items: 4, priority: 'Normal' },
  ];

  const lowStockItems = [
    { name: 'Paracetamol 500mg', current: 50, minimum: 100, unit: 'tablets' },
    { name: 'Amoxicillin 250mg', current: 30, minimum: 75, unit: 'capsules' },
    { name: 'Omeprazole 20mg', current: 15, minimum: 50, unit: 'capsules' },
  ];

  return (
    <DashboardLayout role="pharmacy">
      <div className="mb-6">
        <h1 className="text-pink-900 mb-2">Pharmacy Dashboard</h1>
        <p className="text-gray-600">Manage prescriptions and inventory</p>
      </div>

      {/* Stats Grid */}
      <div className="grid md:grid-cols-4 gap-4 mb-6">
        {stats.map((stat, index) => (
          <div key={index} className="bg-white rounded-lg border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-2">
              <div className={`p-3 rounded-lg ${stat.bg}`}>
                <stat.icon className={`w-6 h-6 ${stat.color}`} />
              </div>
            </div>
            <p className="text-3xl text-gray-900 mb-1">{stat.value}</p>
            <p className="text-sm text-gray-600">{stat.label}</p>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Pending Prescriptions */}
        <div className="bg-white rounded-lg border border-gray-200">
          <div className="border-b border-gray-200 p-4 flex items-center justify-between">
            <h2 className="text-pink-900">Pending Prescriptions</h2>
            <a href="/pharmacy/dispense" className="text-sm text-pink-600 hover:text-pink-700">
              View All
            </a>
          </div>
          <div className="divide-y divide-gray-200">
            {pendingPrescriptions.map((prescription) => (
              <div key={prescription.id} className="p-4 hover:bg-gray-50">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <p className="text-gray-900">{prescription.patient}</p>
                    <p className="text-sm text-gray-500">
                      {prescription.id} • {prescription.doctor}
                    </p>
                  </div>
                  <span className={`px-2 py-1 text-xs rounded-full ${
                    prescription.priority === 'Urgent'
                      ? 'bg-red-100 text-red-700'
                      : 'bg-gray-100 text-gray-700'
                  }`}>
                    {prescription.priority}
                  </span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-600">{prescription.items} items</span>
                  <span className="text-gray-500">{prescription.time}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Low Stock Alerts */}
        <div className="bg-white rounded-lg border border-gray-200">
          <div className="border-b border-gray-200 p-4 flex items-center justify-between">
            <h2 className="text-pink-900">Low Stock Alerts</h2>
            <a href="/pharmacy/inventory" className="text-sm text-pink-600 hover:text-pink-700">
              Manage Inventory
            </a>
          </div>
          <div className="divide-y divide-gray-200">
            {lowStockItems.map((item, index) => (
              <div key={index} className="p-4">
                <div className="flex items-start justify-between mb-2">
                  <p className="text-gray-900">{item.name}</p>
                  <AlertTriangle className="w-4 h-4 text-red-600" />
                </div>
                <div className="flex items-center justify-between text-sm mb-2">
                  <span className="text-gray-600">Current: {item.current} {item.unit}</span>
                  <span className="text-gray-600">Min: {item.minimum}</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div 
                    className="bg-red-600 h-2 rounded-full"
                    style={{ width: `${(item.current / item.minimum) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}