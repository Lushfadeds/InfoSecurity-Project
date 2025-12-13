import { PublicLayout } from '../layouts/PublicLayout';
import { AlertCircle, AlertTriangle, Info, Megaphone } from 'lucide-react';

interface Announcement {
  id: string;
  type: 'maintenance' | 'policy' | 'security' | 'general';
  title: string;
  date: string;
  content: string;
}

const announcements: Announcement[] = [
  {
    id: '1',
    type: 'security',
    title: 'Enhanced Security: Multi-Factor Authentication Now Available',
    date: '2025-01-05',
    content: 'We are pleased to announce that Multi-Factor Authentication (MFA) is now available for all user accounts. We strongly encourage all patients and staff to enable MFA for enhanced account security. You can enable MFA in your account settings under Security Preferences.',
  },
  {
    id: '2',
    type: 'maintenance',
    title: 'Scheduled System Maintenance - January 15, 2025',
    date: '2025-01-03',
    content: 'Our online portal will undergo scheduled maintenance on January 15, 2025, from 2:00 AM to 6:00 AM (SGT). During this time, online services including appointment booking and prescription access will be temporarily unavailable. Emergency services and phone bookings will remain operational. We apologize for any inconvenience.',
  },
  {
    id: '3',
    type: 'policy',
    title: 'Updated Privacy Policy - Effective December 1, 2024',
    date: '2024-12-01',
    content: 'We have updated our Privacy Policy to enhance transparency regarding data collection, usage, and retention practices. The updated policy includes clearer explanations of your rights under PDPA and new provisions for data portability. Please review the updated policy in your Patient Portal.',
  },
  {
    id: '4',
    type: 'general',
    title: 'New Online Prescription Refill Service',
    date: '2024-11-20',
    content: 'Patients on long-term medication can now request prescription refills directly through the Patient Portal. Simply navigate to "Prescriptions" and click "Request Refill" for eligible medications. Refill requests will be reviewed by your doctor within 24 hours.',
  },
  {
    id: '5',
    type: 'policy',
    title: 'Updated Appointment Cancellation Policy',
    date: '2024-11-10',
    content: 'Effective December 1, 2024, appointments cancelled less than 2 hours before the scheduled time will incur a $20 administrative fee. This policy helps us better serve all patients by reducing no-shows. Cancellations made more than 2 hours in advance remain free of charge.',
  },
  {
    id: '6',
    type: 'security',
    title: 'Security Advisory: Phishing Email Awareness',
    date: '2024-10-25',
    content: 'We have been made aware of phishing emails impersonating PinkHealth. Please be vigilant: PinkHealth will NEVER ask for your password, NRIC, or payment details via email. Always verify the sender\'s email address (@pinkhealth.sg) and when in doubt, contact us directly at +65 6123 4567.',
  },
  {
    id: '7',
    type: 'general',
    title: 'Extended Operating Hours for December',
    date: '2024-10-15',
    content: 'To better serve our patients during the holiday season, we will be extending our operating hours in December. Weekday hours will be extended to 10:00 PM, and we will open on selected public holidays. Check our website for the complete December schedule.',
  },
  {
    id: '8',
    type: 'general',
    title: 'Flu Vaccination Program Now Open',
    date: '2024-10-01',
    content: 'Our annual flu vaccination program is now open for registration. Book your flu jab through the Patient Portal or call +65 6123 4567. Special rates available for seniors and children. Protect yourself and your loved ones this flu season.',
  },
];

export function AnnouncementsPage() {
  const getAnnouncementIcon = (type: string) => {
    switch (type) {
      case 'maintenance':
        return <AlertTriangle className="w-6 h-6 text-orange-600" />;
      case 'security':
        return <AlertCircle className="w-6 h-6 text-red-600" />;
      case 'policy':
        return <Info className="w-6 h-6 text-blue-600" />;
      default:
        return <Megaphone className="w-6 h-6 text-pink-600" />;
    }
  };

  const getAnnouncementBg = (type: string) => {
    switch (type) {
      case 'maintenance':
        return 'bg-orange-50 border-orange-200';
      case 'security':
        return 'bg-red-50 border-red-200';
      case 'policy':
        return 'bg-blue-50 border-blue-200';
      default:
        return 'bg-pink-50 border-pink-200';
    }
  };

  const getAnnouncementBadge = (type: string) => {
    switch (type) {
      case 'maintenance':
        return 'bg-orange-100 text-orange-800';
      case 'security':
        return 'bg-red-100 text-red-800';
      case 'policy':
        return 'bg-blue-100 text-blue-800';
      default:
        return 'bg-pink-100 text-pink-800';
    }
  };

  return (
    <PublicLayout>
      {/* Hero Section */}
      <section className="bg-gradient-to-br from-pink-50 to-white py-16">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h1 className="text-gray-900 mb-4">Announcements & Notices</h1>
          <p className="text-gray-600">
            Stay informed with the latest updates, maintenance schedules, and important notices
          </p>
        </div>
      </section>

      {/* Announcements List */}
      <section className="py-16 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="space-y-6">
          {announcements.map((announcement) => (
            <div
              key={announcement.id}
              className={`border rounded-lg p-6 ${getAnnouncementBg(announcement.type)}`}
            >
              <div className="flex items-start gap-4">
                <div className="flex-shrink-0 w-12 h-12 bg-white rounded-lg flex items-center justify-center">
                  {getAnnouncementIcon(announcement.type)}
                </div>
                <div className="flex-1">
                  <div className="flex flex-wrap items-center gap-2 mb-2">
                    <span
                      className={`text-xs px-2 py-1 rounded ${getAnnouncementBadge(
                        announcement.type
                      )}`}
                    >
                      {announcement.type.charAt(0).toUpperCase() + announcement.type.slice(1)}
                    </span>
                    <span className="text-sm text-gray-500">
                      {new Date(announcement.date).toLocaleDateString('en-SG', {
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric',
                      })}
                    </span>
                  </div>
                  <h3 className="text-gray-900 mb-2">{announcement.title}</h3>
                  <p className="text-gray-600">{announcement.content}</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Subscribe to Updates */}
        <div className="mt-12 p-8 bg-white rounded-xl border border-gray-200 text-center">
          <h2 className="text-gray-900 mb-4">Stay Updated</h2>
          <p className="text-gray-600 mb-6">
            Subscribe to receive important announcements and updates via email or SMS
          </p>
          <div className="max-w-md mx-auto">
            <form className="flex gap-2">
              <input
                type="email"
                placeholder="Enter your email"
                className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-pink-500"
              />
              <button
                type="submit"
                className="px-6 py-2 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
              >
                Subscribe
              </button>
            </form>
          </div>
        </div>
      </section>
    </PublicLayout>
  );
}
