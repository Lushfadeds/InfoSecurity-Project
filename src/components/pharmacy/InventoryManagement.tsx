import { useState } from 'react';
import { Search, Plus, Package, AlertTriangle, TrendingUp, Edit } from 'lucide-react';
import { DashboardLayout } from '../layouts/DashboardLayout';

interface InventoryItem {
  id: string;
  name: string;
  category: string;
  currentStock: number;
  minimumStock: number;
  unit: string;
  expiryDate: string;
  supplier: string;
  cost: string;
}

export function InventoryManagement() {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState('all');
  const [showAddModal, setShowAddModal] = useState(false);

  const inventory: InventoryItem[] = [
    { id: 'MED001', name: 'Paracetamol 500mg', category: 'Analgesics', currentStock: 50, minimumStock: 100, unit: 'tablets', expiryDate: '2025-06-15', supplier: 'PharmaCorp', cost: '$0.10' },
    { id: 'MED002', name: 'Amoxicillin 250mg', category: 'Antibiotics', currentStock: 30, minimumStock: 75, unit: 'capsules', expiryDate: '2025-03-20', supplier: 'MediSupply', cost: '$0.45' },
    { id: 'MED003', name: 'Omeprazole 20mg', category: 'Gastrointestinal', currentStock: 15, minimumStock: 50, unit: 'capsules', expiryDate: '2025-01-10', supplier: 'PharmaCorp', cost: '$0.35' },
    { id: 'MED004', name: 'Metformin 500mg', category: 'Diabetes', currentStock: 120, minimumStock: 80, unit: 'tablets', expiryDate: '2025-08-30', supplier: 'HealthDist', cost: '$0.25' },
    { id: 'MED005', name: 'Cetirizine 10mg', category: 'Antihistamines', currentStock: 85, minimumStock: 60, unit: 'tablets', expiryDate: '2025-05-18', supplier: 'MediSupply', cost: '$0.20' },
  ];

  const filteredInventory = inventory.filter(item => {
    const matchesSearch = item.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         item.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = filterCategory === 'all' || item.category === filterCategory;
    return matchesSearch && matchesCategory;
  });

  const categories = ['all', ...Array.from(new Set(inventory.map(i => i.category)))];

  const getStockStatus = (current: number, minimum: number) => {
    const percentage = (current / minimum) * 100;
    if (percentage <= 50) return { label: 'Critical', color: 'text-red-600', bg: 'bg-red-100' };
    if (percentage <= 100) return { label: 'Low', color: 'text-orange-600', bg: 'bg-orange-100' };
    return { label: 'Adequate', color: 'text-green-600', bg: 'bg-green-100' };
  };

  return (
    <DashboardLayout role="pharmacy">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6 flex items-start justify-between">
          <div>
            <h1 className="text-pink-900 mb-2">Inventory Management</h1>
            <p className="text-gray-600">Track and manage medication stock levels</p>
          </div>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-pink-600 text-white rounded-lg hover:bg-pink-700"
          >
            <Plus className="w-5 h-5" />
            Add Item
          </button>
        </div>

        {/* Stats */}
        <div className="grid md:grid-cols-4 gap-4 mb-6">
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-blue-50 rounded-lg">
                <Package className="w-6 h-6 text-blue-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">{inventory.length}</p>
                <p className="text-sm text-gray-600">Total Items</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-red-50 rounded-lg">
                <AlertTriangle className="w-6 h-6 text-red-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">
                  {inventory.filter(i => i.currentStock < i.minimumStock).length}
                </p>
                <p className="text-sm text-gray-600">Low Stock</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-orange-50 rounded-lg">
                <TrendingUp className="w-6 h-6 text-orange-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">2</p>
                <p className="text-sm text-gray-600">Expiring Soon</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-4">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-green-50 rounded-lg">
                <Package className="w-6 h-6 text-green-600" />
              </div>
              <div>
                <p className="text-2xl text-gray-900">$12,450</p>
                <p className="text-sm text-gray-600">Total Value</p>
              </div>
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="bg-white rounded-lg border border-gray-200 p-4 mb-6">
          <div className="grid md:grid-cols-2 gap-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
              <input
                type="text"
                placeholder="Search by name or ID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
              />
            </div>
            <select
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
            >
              {categories.map(cat => (
                <option key={cat} value={cat}>
                  {cat === 'all' ? 'All Categories' : cat}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Inventory Table */}
        <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Item ID</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Name</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Category</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Stock Level</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Status</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Expiry Date</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Supplier</th>
                  <th className="px-4 py-3 text-left text-sm text-gray-700">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {filteredInventory.map((item) => {
                  const status = getStockStatus(item.currentStock, item.minimumStock);
                  return (
                    <tr key={item.id} className="hover:bg-gray-50">
                      <td className="px-4 py-3 text-sm text-gray-900">{item.id}</td>
                      <td className="px-4 py-3">
                        <p className="text-sm text-gray-900">{item.name}</p>
                        <p className="text-xs text-gray-500">{item.cost} per {item.unit}</p>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-600">{item.category}</td>
                      <td className="px-4 py-3">
                        <p className="text-sm text-gray-900">
                          {item.currentStock} / {item.minimumStock} {item.unit}
                        </p>
                        <div className="w-full bg-gray-200 rounded-full h-1.5 mt-1">
                          <div 
                            className={`h-1.5 rounded-full ${
                              item.currentStock <= item.minimumStock * 0.5 ? 'bg-red-600' :
                              item.currentStock <= item.minimumStock ? 'bg-orange-600' : 'bg-green-600'
                            }`}
                            style={{ width: `${Math.min((item.currentStock / item.minimumStock) * 100, 100)}%` }}
                          />
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 text-xs rounded-full ${status.bg} ${status.color}`}>
                          {status.label}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-600">{item.expiryDate}</td>
                      <td className="px-4 py-3 text-sm text-gray-600">{item.supplier}</td>
                      <td className="px-4 py-3">
                        <button className="p-1 hover:bg-gray-200 rounded">
                          <Edit className="w-4 h-4 text-gray-600" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}