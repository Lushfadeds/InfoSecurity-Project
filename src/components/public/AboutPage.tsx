import { PublicLayout } from '../layouts/PublicLayout';
import { Shield, Heart, Award, Users, Lock, Eye } from 'lucide-react';

export function AboutPage() {
  return (
    <PublicLayout>
      {/* Hero Section */}
      <section className="bg-gradient-to-br from-pink-50 to-white py-16">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h1 className="text-gray-900 mb-4">About PinkHealth</h1>
          <p className="text-gray-600">
            Leading the future of secure healthcare management in Singapore
          </p>
        </div>
      </section>

      {/* Mission & Vision */}
      <section className="py-16 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid md:grid-cols-2 gap-12">
          <div>
            <div className="w-12 h-12 bg-pink-100 rounded-lg flex items-center justify-center mb-4">
              <Heart className="w-6 h-6 text-pink-600" fill="currentColor" />
            </div>
            <h2 className="text-gray-900 mb-4">Our Mission</h2>
            <p className="text-gray-600 mb-4">
              To provide accessible, efficient, and secure healthcare management solutions 
              that empower patients and healthcare providers alike.
            </p>
            <p className="text-gray-600">
              We believe that quality healthcare begins with trust, and trust begins with 
              uncompromising data security and privacy protection.
            </p>
          </div>

          <div>
            <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-4">
              <Eye className="w-6 h-6 text-blue-600" />
            </div>
            <h2 className="text-gray-900 mb-4">Our Vision</h2>
            <p className="text-gray-600 mb-4">
              To be Singapore's most trusted healthcare management platform, setting the 
              gold standard for medical data security and patient care excellence.
            </p>
            <p className="text-gray-600">
              We envision a future where healthcare is seamlessly integrated with technology, 
              without compromising patient privacy or data security.
            </p>
          </div>
        </div>
      </section>

      {/* Core Values */}
      <section className="bg-gray-50 py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <h2 className="text-center text-gray-900 mb-12">Our Core Values</h2>
          <div className="grid md:grid-cols-3 gap-8">
            <div className="bg-white p-6 rounded-xl border border-gray-200">
              <div className="w-12 h-12 bg-pink-100 rounded-lg flex items-center justify-center mb-4">
                <Shield className="w-6 h-6 text-pink-600" />
              </div>
              <h3 className="text-gray-900 mb-2">Privacy First</h3>
              <p className="text-gray-600">
                Patient data privacy is our top priority. We implement military-grade 
                encryption, strict access controls, and comprehensive audit logging to 
                ensure your information remains confidential.
              </p>
            </div>

            <div className="bg-white p-6 rounded-xl border border-gray-200">
              <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-4">
                <Lock className="w-6 h-6 text-blue-600" />
              </div>
              <h3 className="text-gray-900 mb-2">Security Excellence</h3>
              <p className="text-gray-600">
                Our platform is built with enterprise-grade security from the ground up. 
                Every component is designed with data protection, DLP policies, and 
                regulatory compliance in mind.
              </p>
            </div>

            <div className="bg-white p-6 rounded-xl border border-gray-200">
              <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mb-4">
                <Heart className="w-6 h-6 text-green-600" fill="currentColor" />
              </div>
              <h3 className="text-gray-900 mb-2">Patient-Centric Care</h3>
              <p className="text-gray-600">
                We design every feature with patients in mind. Our intuitive interfaces 
                and seamless workflows make healthcare management accessible to everyone, 
                regardless of technical expertise.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Leadership Team */}
      <section className="py-16 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <h2 className="text-center text-gray-900 mb-12">Leadership Team</h2>
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-8">
          <div className="text-center">
            <div className="w-32 h-32 bg-gradient-to-br from-pink-200 to-pink-300 rounded-full mx-auto mb-4 flex items-center justify-center">
              <Users className="w-16 h-16 text-white" />
            </div>
            <h3 className="text-gray-900 mb-1">Dr. Sarah Tan</h3>
            <p className="text-pink-600 mb-2">Chief Medical Officer</p>
            <p className="text-gray-600 text-sm">
              20+ years in healthcare administration
            </p>
          </div>

          <div className="text-center">
            <div className="w-32 h-32 bg-gradient-to-br from-blue-200 to-blue-300 rounded-full mx-auto mb-4 flex items-center justify-center">
              <Users className="w-16 h-16 text-white" />
            </div>
            <h3 className="text-gray-900 mb-1">David Lim</h3>
            <p className="text-pink-600 mb-2">Chief Technology Officer</p>
            <p className="text-gray-600 text-sm">
              Expert in healthcare IT security
            </p>
          </div>

          <div className="text-center">
            <div className="w-32 h-32 bg-gradient-to-br from-purple-200 to-purple-300 rounded-full mx-auto mb-4 flex items-center justify-center">
              <Users className="w-16 h-16 text-white" />
            </div>
            <h3 className="text-gray-900 mb-1">Michelle Wong</h3>
            <p className="text-pink-600 mb-2">Chief Information Security Officer</p>
            <p className="text-gray-600 text-sm">
              Certified in ISO 27001 & PDPA compliance
            </p>
          </div>

          <div className="text-center">
            <div className="w-32 h-32 bg-gradient-to-br from-green-200 to-green-300 rounded-full mx-auto mb-4 flex items-center justify-center">
              <Users className="w-16 h-16 text-white" />
            </div>
            <h3 className="text-gray-900 mb-1">James Koh</h3>
            <p className="text-pink-600 mb-2">Chief Operations Officer</p>
            <p className="text-gray-600 text-sm">
              Streamlining healthcare workflows
            </p>
          </div>
        </div>
      </section>

      {/* Certifications & Compliance */}
      <section className="bg-gray-50 py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <h2 className="text-center text-gray-900 mb-12">Accreditations & Compliance</h2>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-white p-6 rounded-xl border border-gray-200 text-center">
              <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Award className="w-8 h-8 text-green-600" />
              </div>
              <h3 className="text-gray-900 mb-2">PDPA Certified</h3>
              <p className="text-gray-600 text-sm">
                Full compliance with Singapore's Personal Data Protection Act
              </p>
            </div>

            <div className="bg-white p-6 rounded-xl border border-gray-200 text-center">
              <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Award className="w-8 h-8 text-blue-600" />
              </div>
              <h3 className="text-gray-900 mb-2">ISO 27001</h3>
              <p className="text-gray-600 text-sm">
                International standard for information security management
              </p>
            </div>

            <div className="bg-white p-6 rounded-xl border border-gray-200 text-center">
              <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Award className="w-8 h-8 text-purple-600" />
              </div>
              <h3 className="text-gray-900 mb-2">HIPAA Aligned</h3>
              <p className="text-gray-600 text-sm">
                Healthcare data protection best practices
              </p>
            </div>

            <div className="bg-white p-6 rounded-xl border border-gray-200 text-center">
              <div className="w-16 h-16 bg-orange-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Award className="w-8 h-8 text-orange-600" />
              </div>
              <h3 className="text-gray-900 mb-2">MOH Approved</h3>
              <p className="text-gray-600 text-sm">
                Approved by Ministry of Health Singapore
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Contact CTA */}
      <section className="py-16 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        <h2 className="text-gray-900 mb-4">Have Questions?</h2>
        <p className="text-gray-600 mb-6">
          Our team is here to help you understand how PinkHealth can transform your healthcare experience.
        </p>
        <a
          href="/contact"
          className="inline-block px-6 py-3 bg-pink-500 text-white rounded-lg hover:bg-pink-600 transition-colors"
        >
          Contact Us
        </a>
      </section>
    </PublicLayout>
  );
}
