import { PublicLayout } from '../layouts/PublicLayout';
import { ChevronDown, ChevronUp } from 'lucide-react';
import { useState } from 'react';

interface FAQItem {
  question: string;
  answer: string;
  category: string;
}

const faqs: FAQItem[] = [
  {
    category: 'Appointments',
    question: 'How do I book an appointment?',
    answer: 'Log in to your Patient Portal, navigate to "Book Appointment", select your preferred doctor and time slot, and confirm your booking. You will receive an instant confirmation email and SMS.',
  },
  {
    category: 'Appointments',
    question: 'Can I cancel or reschedule my appointment?',
    answer: 'Yes, you can cancel or reschedule appointments up to 2 hours before the scheduled time through your Patient Portal under "Appointment History". Please note that late cancellations may incur a fee.',
  },
  {
    category: 'Appointments',
    question: 'What if I\'m running late for my appointment?',
    answer: 'Please call our clinic at +65 6123 4567 to inform us. We will do our best to accommodate you, though you may experience a longer wait time.',
  },
  {
    category: 'Prescriptions',
    question: 'How do I access my prescriptions?',
    answer: 'All your prescriptions are available in your Patient Portal under "Prescriptions". You can view, download, and print them. Digital prescriptions are also automatically sent to our pharmacy.',
  },
  {
    category: 'Prescriptions',
    question: 'Can I collect my medication from any pharmacy?',
    answer: 'Digital prescriptions can be collected from our in-house pharmacy. For external pharmacies, please download and print your prescription from the portal.',
  },
  {
    category: 'Prescriptions',
    question: 'How long are prescriptions valid?',
    answer: 'Most prescriptions are valid for 6 months from the date of issue, unless otherwise specified by your doctor. Check your prescription details in the portal for exact validity.',
  },
  {
    category: 'Privacy & Security',
    question: 'How is my medical data protected?',
    answer: 'We use military-grade AES-256 encryption for all patient data. Access is strictly controlled through ABAC (Attribute-Based Access Control) and all data access is logged in immutable audit trails. We are PDPA compliant and ISO 27001 certified.',
  },
  {
    category: 'Privacy & Security',
    question: 'Who can access my medical records?',
    answer: 'Only authorized healthcare professionals directly involved in your care can access your records. All access is logged and can be reviewed in your Patient Portal under account activity.',
  },
  {
    category: 'Privacy & Security',
    question: 'Can I delete my medical records?',
    answer: 'Medical records are retained as per regulatory requirements (typically 6 years). You can request data deletion after the retention period through the Data Retention request form in your portal.',
  },
  {
    category: 'Medical Certificates',
    question: 'How do I get my medical certificate (MC)?',
    answer: 'MCs are issued by your doctor during consultation and automatically available in your Patient Portal under "Medical Certificates". You can download or print them anytime.',
  },
  {
    category: 'Medical Certificates',
    question: 'Are digital MCs accepted by employers?',
    answer: 'Yes, our digital MCs are legally valid and include a unique verification code. Employers can verify authenticity through our verification portal.',
  },
  {
    category: 'Billing & Payment',
    question: 'What payment methods do you accept?',
    answer: 'We accept cash, NETS, credit/debit cards (Visa, Mastercard, AMEX), PayNow, and online banking. Payment can be made at the clinic or through the Patient Portal.',
  },
  {
    category: 'Billing & Payment',
    question: 'Can I use my insurance or Medisave?',
    answer: 'Yes, we accept major insurance providers and Medisave for eligible treatments. Please inform our staff during registration to process your claims.',
  },
  {
    category: 'Billing & Payment',
    question: 'How do I get my receipt for claims?',
    answer: 'All receipts are automatically available in your Patient Portal under "Billing & Payment History". You can download itemized receipts for insurance claims.',
  },
  {
    category: 'Account & Access',
    question: 'How do I create a patient account?',
    answer: 'Click on "Register as Patient" on the home page, fill in your details including NRIC, and verify your account via OTP sent to your mobile number.',
  },
  {
    category: 'Account & Access',
    question: 'I forgot my password. What should I do?',
    answer: 'Click "Forgot Password" on the login page and follow the instructions. You will receive an OTP via email and SMS to reset your password securely.',
  },
  {
    category: 'Account & Access',
    question: 'What is MFA and do I need it?',
    answer: 'Multi-Factor Authentication (MFA) adds an extra layer of security to your account. While optional, we highly recommend enabling it for better protection of your medical data.',
  },
];

export function FAQPage() {
  const [openIndex, setOpenIndex] = useState<number | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>('All');

  const categories = ['All', ...Array.from(new Set(faqs.map(faq => faq.category)))];

  const filteredFaqs = selectedCategory === 'All' 
    ? faqs 
    : faqs.filter(faq => faq.category === selectedCategory);

  return (
    <PublicLayout>
      {/* Hero Section */}
      <section className="bg-gradient-to-br from-pink-50 to-white py-16">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h1 className="text-gray-900 mb-4">Frequently Asked Questions</h1>
          <p className="text-gray-600">
            Find answers to common questions about using PinkHealth
          </p>
        </div>
      </section>

      {/* FAQ Content */}
      <section className="py-16 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Category Filter */}
        <div className="mb-8">
          <div className="flex flex-wrap gap-2">
            {categories.map((category) => (
              <button
                key={category}
                onClick={() => setSelectedCategory(category)}
                className={`px-4 py-2 rounded-lg transition-colors ${
                  selectedCategory === category
                    ? 'bg-pink-500 text-white'
                    : 'bg-white text-gray-700 border border-gray-300 hover:bg-pink-50'
                }`}
              >
                {category}
              </button>
            ))}
          </div>
        </div>

        {/* FAQ Items */}
        <div className="space-y-4">
          {filteredFaqs.map((faq, index) => (
            <div
              key={index}
              className="bg-white border border-gray-200 rounded-lg overflow-hidden"
            >
              <button
                onClick={() => setOpenIndex(openIndex === index ? null : index)}
                className="w-full px-6 py-4 flex items-center justify-between hover:bg-gray-50 transition-colors"
              >
                <div className="text-left">
                  <span className="text-sm text-pink-600 mb-1 block">{faq.category}</span>
                  <span className="text-gray-900">{faq.question}</span>
                </div>
                {openIndex === index ? (
                  <ChevronUp className="w-5 h-5 text-gray-500 flex-shrink-0 ml-4" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-gray-500 flex-shrink-0 ml-4" />
                )}
              </button>
              {openIndex === index && (
                <div className="px-6 py-4 bg-gray-50 border-t border-gray-200">
                  <p className="text-gray-600">{faq.answer}</p>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Still have questions CTA */}
        <div className="mt-12 p-8 bg-gradient-to-br from-pink-50 to-white rounded-xl border border-pink-200 text-center">
          <h2 className="text-gray-900 mb-4">Still have questions?</h2>
          <p className="text-gray-600 mb-6">
            Can't find what you're looking for? Our support team is here to help.
          </p>
          <a
            href="/contact"
            className="inline-block px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
          >
            Contact Support
          </a>
        </div>
      </section>
    </PublicLayout>
  );
}
