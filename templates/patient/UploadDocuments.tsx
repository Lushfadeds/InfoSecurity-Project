import { DashboardLayout } from '../layouts/DashboardLayout';
import { Home, Calendar, FileText, Pill, CreditCard, User, Upload, CheckCircle, XCircle, Loader, File } from 'lucide-react';
import { useState } from 'react';
import { scanDocument, validateFileBeforeUpload, DLPScanResult } from '../../utils/dlpScanner';
import { toast } from '../ui/simple-toast';

const sidebarItems = [
  { icon: <Home className="w-5 h-5" />, label: 'Dashboard', path: '/patient/dashboard' },
  { icon: <Calendar className="w-5 h-5" />, label: 'Book Appointment', path: '/patient/book-appointment' },
  { icon: <FileText className="w-5 h-5" />, label: 'Medical Certificates', path: '/patient/medical-certificates' },
  { icon: <Pill className="w-5 h-5" />, label: 'Prescriptions', path: '/patient/prescriptions' },
  { icon: <CreditCard className="w-5 h-5" />, label: 'Billing & Payment', path: '/patient/billing' },
  { icon: <User className="w-5 h-5" />, label: 'Personal Particulars', path: '/patient/profile' },
  { icon: <Upload className="w-5 h-5" />, label: 'Upload Documents', path: '/patient/upload' },
];

interface UploadedDocument {
  id: string;
  name: string;
  uploadDate: string;
  size: string;
}

const initialUploadedDocuments: UploadedDocument[] = [
  {
    id: '1',
    name: 'Lab-Results-Blood-Test.pdf',
    uploadDate: '2024-12-05',
    size: '245 KB',
  },
  {
    id: '2',
    name: 'Referral-Letter-Specialist.pdf',
    uploadDate: '2024-11-20',
    size: '189 KB',
  },
];

export function UploadDocuments() {
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState<Map<string, DLPScanResult>>(new Map());
  const [uploadError, setUploadError] = useState('');
  const [uploadedDocuments, setUploadedDocuments] = useState<UploadedDocument[]>(initialUploadedDocuments);

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files) return;
    
    const files = Array.from(e.target.files);
    setUploadError('');
    setScanResults(new Map());
    
    // Validate all files first
    const validFiles: File[] = [];
    for (const file of files) {
      const validation = validateFileBeforeUpload(file);
      if (!validation.valid) {
        setUploadError(validation.error || 'Invalid file');
        return;
      }
      validFiles.push(file);
    }
    
    setSelectedFiles(validFiles);
    
    // Auto-scan files (background process - patient doesn't see technical details)
    setScanning(true);
    const results = new Map<string, DLPScanResult>();
    
    for (const file of validFiles) {
      // Simulate scanning delay
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      try {
        const result = await scanDocument(
          file,
          'john.doe@example.com',
          'patient',
          '203.45.67.89'
        );
        results.set(file.name, result);
      } catch (error) {
        console.error('Scan error:', error);
      }
    }
    
    setScanResults(results);
    setScanning(false);
  };

  const handleConfirmUpload = () => {
    // Process each file and add to uploaded documents
    const newDocuments: UploadedDocument[] = [];

    selectedFiles.forEach((file) => {
      const result = scanResults.get(file.name);
      if (result && !result.blocked) {
        // Generate new document ID
        const docId = `DOC-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        
        // Add to uploaded documents (simplified view for patients)
        newDocuments.push({
          id: docId,
          name: file.name,
          uploadDate: new Date().toISOString().split('T')[0],
          size: `${(file.size / 1024).toFixed(2)} KB`,
        });
      }
    });

    // Update state
    setUploadedDocuments([...newDocuments, ...uploadedDocuments]);

    // Show success notification (simple message for patients)
    toast.success('Documents uploaded successfully', {
      description: `${newDocuments.length} document(s) uploaded`
    });

    // Reset upload state
    setSelectedFiles([]);
    setScanResults(new Map());
    setUploadError('');

    // Reset file input
    const fileInput = document.getElementById('file-upload') as HTMLInputElement;
    if (fileInput) fileInput.value = '';
  };

  const handleDownload = (doc: UploadedDocument) => {
    toast.success(`Downloading ${doc.name}...`);
    // In production, this would trigger actual file download from server
  };

  return (
    <DashboardLayout role="patient" sidebarItems={sidebarItems} userName="John Doe">
      <div className="max-w-4xl">
        <div className="mb-6">
          <h1 className="text-gray-900">Upload Documents</h1>
          <p className="text-gray-600 mt-2">Upload your medical documents securely</p>
        </div>

        {uploadError && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
            <div className="flex items-start gap-3">
              <XCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-red-800">{uploadError}</p>
            </div>
          </div>
        )}

        <div className="bg-white rounded-xl border border-gray-200 p-6 mb-6">
          <h2 className="text-gray-900 mb-4">Upload New Document</h2>

          <div className="border-2 border-dashed border-gray-300 rounded-xl p-8 text-center hover:border-pink-400 transition-colors cursor-pointer">
            <Upload className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-700 mb-2">Click to upload or drag and drop</p>
            <p className="text-sm text-gray-500 mb-4">PDF, JPG, PNG (Max 10MB)</p>
            <input
              type="file"
              multiple
              accept=".pdf,.jpg,.jpeg,.png"
              onChange={handleFileSelect}
              className="hidden"
              id="file-upload"
              disabled={scanning}
            />
            <label
              htmlFor="file-upload"
              className={`inline-block px-6 py-2 bg-pink-500 text-white rounded-lg hover:bg-pink-600 ${scanning ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
            >
              {scanning ? 'Processing...' : 'Select Files'}
            </label>
          </div>

          {scanning && (
            <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
              <div className="flex items-center gap-3">
                <Loader className="w-5 h-5 text-blue-600 animate-spin" />
                <p className="text-sm text-blue-800">Processing your documents...</p>
              </div>
            </div>
          )}

          {selectedFiles.length > 0 && !scanning && (
            <div className="mt-4 space-y-3">
              {selectedFiles.map((file, index) => {
                const result = scanResults.get(file.name);
                return (
                  <div key={index} className="p-4 bg-gray-50 rounded-lg border border-gray-200">
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <File className="w-6 h-6 text-pink-600" />
                        <div>
                          <p className="text-sm text-gray-900">{file.name}</p>
                          <p className="text-xs text-gray-600">{(file.size / 1024).toFixed(2)} KB</p>
                        </div>
                      </div>
                      {result && (
                        <div className="flex items-center gap-2">
                          {result.blocked ? (
                            <span className="flex items-center gap-1 px-3 py-1 bg-red-100 text-red-800 text-xs rounded-full">
                              <XCircle className="w-3 h-3" />
                              Cannot Upload
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 px-3 py-1 bg-green-100 text-green-800 text-xs rounded-full">
                              <CheckCircle className="w-3 h-3" />
                              Ready
                            </span>
                          )}
                        </div>
                      )}
                    </div>

                    {result && result.blocked && (
                      <div className="p-3 bg-red-50 border border-red-200 rounded">
                        <p className="text-xs text-red-800">
                          <strong>Unable to upload:</strong> This file contains sensitive information that cannot be uploaded through the patient portal. Please contact the clinic directly for assistance.
                        </p>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {selectedFiles.length > 0 && !scanning && scanResults.size > 0 && (
            <button 
              onClick={handleConfirmUpload}
              className="mt-4 w-full px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={Array.from(scanResults.values()).some(r => r.blocked)}
            >
              {Array.from(scanResults.values()).some(r => r.blocked) 
                ? 'Please Remove Blocked Files'
                : 'Confirm Upload'}
            </button>
          )}
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="text-gray-900 mb-4">My Documents</h2>

          <div className="space-y-3">
            {uploadedDocuments.map((doc) => (
              <div key={doc.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-pink-100 rounded-lg flex items-center justify-center">
                    <FileText className="w-6 h-6 text-pink-600" />
                  </div>
                  <div>
                    <p className="text-gray-900 text-sm">{doc.name}</p>
                    <p className="text-gray-600 text-xs">
                      Uploaded: {new Date(doc.uploadDate).toLocaleDateString('en-SG')} • {doc.size}
                    </p>
                  </div>
                </div>
                <button className="text-pink-600 hover:text-pink-700 text-sm" onClick={() => handleDownload(doc)}>
                  Download
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}