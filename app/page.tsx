import { PhishingDetector } from "@/components/phishing-detector"

export default function Home() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-slate-100 dark:from-slate-950 dark:to-slate-900">
      <main className="container mx-auto px-4 py-8">
        <div className="mx-auto max-w-4xl">
          <div className="mb-8 text-center">
            <h1 className="text-4xl font-bold tracking-tight text-slate-900 dark:text-slate-50 sm:text-5xl">
              Phishing URL Detector
            </h1>
            <p className="mt-4 text-lg text-slate-600 dark:text-slate-400">
              Check if a URL is legitimate or a potential phishing attempt using advanced machine learning.
            </p>
          </div>
          <PhishingDetector />
        </div>
      </main>
      <footer className="border-t border-slate-200 dark:border-slate-800">
        <div className="container mx-auto px-4 py-6">
          <p className="text-center text-sm text-slate-500 dark:text-slate-400">
            © {new Date().getFullYear()} Phishing Detector. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  )
}
