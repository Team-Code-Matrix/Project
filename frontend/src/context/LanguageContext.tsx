import React, { createContext, useContext, useState, useEffect, type ReactNode } from 'react';

export type Language = 'en' | 'ar';

interface Translations {
  [key: string]: {
    en: string;
    ar: string;
  };
}

export const TRANSLATIONS: Translations = {
  // Navigation
  nav_overview: { en: 'Overview', ar: 'نظرة عامة' },
  nav_features: { en: 'Features', ar: 'الميزات' },
  nav_how_it_works: { en: 'How It Works', ar: 'كيف يعمل' },
  nav_threat_intel: { en: 'Threat Intel', ar: 'استخبارات التهديدات' },
  nav_about: { en: 'About', ar: 'حول المنصة' },
  nav_methodology: { en: 'Methodology', ar: 'المنهجية' },
  nav_scan_url: { en: 'Scan URL', ar: 'فحص الرابط' },
  nav_demo_sandbox: { en: 'Demo Sandbox', ar: 'بيئة تجريبية' },

  // Hero
  hero_eyebrow: {
    en: 'CYBERSECURITY & WEB REPUTATION ENGINE',
    ar: 'محرك الأمن السيبراني وتقييم سمعة المواقع',
  },
  hero_headline_1: { en: 'Not every link deserves', ar: 'ليس كل رابط يستحق' },
  hero_headline_2: { en: 'your trust.', ar: 'ثقتك.' },
  hero_subtext: {
    en: 'Go beyond the lock icon. Analyse websites through multiple security intelligence models and understand the risks before you interact.',
    ar: 'تجاوز مجرد أيقونة القفل. حلل المواقع الإلكترونية عبر نماذج استخبارات أمنية متعددة وافهم المخاطر قبل أن تتفاعل.',
  },
  hero_inspect_sub: {
    en: 'Inspect before you interact.',
    ar: 'تحقق من الرابط قبل أن تتفاعل معه.',
  },
  hero_privacy_notice: {
    en: 'Target URLs are evaluated via proxy sandboxes and are never contacted directly by your browser.',
    ar: 'يتم تقييم الروابط عبر بيئات معزولة وآمنة ولا يتصل متصفحك بها مباشرة مطلقاً.',
  },

  // Scanner
  scanner_placeholder: {
    en: 'Enter website URL or domain (e.g. https://example.com)',
    ar: 'أدخل رابط الموقع أو النطاق (مثال: https://example.com)',
  },
  scanner_scan_button: { en: 'Scan URL', ar: 'فحص الرابط' },
  scanner_assessing: { en: 'Assessing...', ar: 'جاري التقييم...' },
  scanner_paste: { en: 'Paste', ar: 'لصق' },
  scanner_benchmark_chips: {
    en: 'Quick Benchmark Scenarios:',
    ar: 'سيناريوهات اختبار سريعة:',
  },

  // Dashboard
  trust_score_title: { en: 'TRUST SCORE', ar: 'مؤشر الثقة' },
  model_verdicts_title: {
    en: 'Multi-Model Analysis Verdicts',
    ar: 'أحكام نماذج التحليل المستقلة',
  },
  findings_title: {
    en: 'Security Findings & Observed Indicators',
    ar: 'النتائج الأمنية والمؤشرات المرصودة',
  },
  recommendations_title: {
    en: 'Recommended Protective Actions',
    ar: 'الإجراءات الوقائية الموصى بها',
  },
  scan_another_url: { en: 'Scan Another URL', ar: 'فحص رابط آخر' },
  share_summary: { en: 'Share Summary', ar: 'مشاركة الملخص' },
  export_json: { en: 'Export JSON', ar: 'تصدير JSON' },
  how_score_calculated: {
    en: 'How score is calculated?',
    ar: 'كيف يُحسب المؤشر؟',
  },
};

interface LanguageContextType {
  language: Language;
  setLanguage: (lang: Language) => void;
  t: (key: string) => string;
  isRtl: boolean;
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

export const LanguageProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [language, setLanguage] = useState<Language>('en');

  const isRtl = language === 'ar';

  useEffect(() => {
    document.documentElement.dir = isRtl ? 'rtl' : 'ltr';
    document.documentElement.lang = language;
  }, [language, isRtl]);

  const t = (key: string): string => {
    if (TRANSLATIONS[key]) {
      return TRANSLATIONS[key][language] || TRANSLATIONS[key]['en'];
    }
    return key;
  };

  return (
    <LanguageContext.Provider value={{ language, setLanguage, t, isRtl }}>
      {children}
    </LanguageContext.Provider>
  );
};

export function useLanguage() {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error('useLanguage must be used within a LanguageProvider');
  }
  return context;
}
