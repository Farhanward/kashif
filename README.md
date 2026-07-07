# كاشف — Local Code And Binary Security Mapper

تنفيذ أول للفكرة 2: أداة محلية بالعربية تفحص مشروع كود أو ملفاً ثنائياً وتنتج خريطة ملفات ورموز ومؤشرات خطورة مرتبطة بـ CWE.

## ما يفعله

- يجرد الملفات واللغات والأحجام.
- يستخرج رموز Python: دوال وكلاسات.
- يكشف أنماطاً خطرة: `eval/exec`, `shell=True`, `os.system`, `pickle`, `yaml.load`, SQL string building, أسرار hardcoded، TLS verify false، hash ضعيف.
- يستخدم AST في Python للدوال الخطرة حتى لا يحسب التعليقات أو strings كتنفيذ فعلي.
- يحلل الثنائيات بخفة: magic bytes، entropy، وسلاسل مشبوهة.
- يجلب بيانات NVD CVE كبيرة من الإنترنت لاستخدامها كمرجع معرفة أمني.

## تشغيل سريع

```powershell
cd C:\Projects\kashif
python -m kashif.cli scan --path examples\vulnerable_project --out reports\vulnerable_project.md
python -m unittest discover -s tests -v
```

آخر تحقق:

- الاختبارات: 3/3 ناجحة.
- عينة `examples\vulnerable_project`: 7 ملاحظات، منها 2 critical و5 high.
- التقرير: `reports\vulnerable_project.md`.

## بيانات الإنترنت

المصدر: NVD CVE API 2.0 الرسمي من NIST.

```powershell
python -m kashif.cli download-nvd --limit 12000 --out data\external\nvd_cves_12000.jsonl --report reports\nvd_summary.md
```

آخر تنزيل:

- 12,000 CVE.
- Critical/High: 5,375.
- أعلى CWE ظاهرة: `CWE-119`, `CWE-79`, `CWE-20`, `CWE-200`, `CWE-22`, `CWE-94`, `CWE-89`.
- التقرير: `reports\nvd_summary.md`.

## الملفات

- `kashif\scanner.py`: فاحص الكود والثنائيات.
- `kashif\datasets.py`: تنزيل بيانات NVD.
- `kashif\reports.py`: تقارير Markdown.
- `kashif\cli.py`: واجهة أوامر.

## الحالة

منتج CLI أولي للفكرة. المرحلة التالية: ربط نتائج NVD/CWE أعمق مع كل finding، ودعم decompiler خارجي عند توفر نموذج LLM4Decompile محلي.

## تحسينات إنتاجية

- فحص Python صار ذا طبقتين: AST لدوال التنفيذ الفعلي، وregex للأنماط النصية العابرة للغات مثل الأسرار وSQL strings.
- أضيف اختبار يمنع false positives من `eval`, `pickle.loads`, و`shell=True` عندما تظهر داخل تعليق أو string.
- آخر اختبار ذاتي بعد التحسين: 3/3 ناجحة.

## التشغيل المؤسسي (Enterprise) — v1.0.0

- **خدمة HTTP للفحص**: `python -m kashif.cli serve` → `POST /api/scan {"path": "..."}`.
- **قيد أمني**: الفحص مسموح فقط تحت الجذور في `KASHIF_SCAN_ROOTS` (افتراضي `C:\Projects`) — أي مسار خارجها يرفض بـ 403.
- **نقاط فحص**: `/api/health` (مفتوح) · `/api/version` · `/api/metrics`.
- **تهيئة عبر البيئة**: متغيرات `KASHIF_*` — انظر `docs/OPERATIONS.md`.
- **مصادقة**: `KASHIF_API_KEY` → ترويسة `X-API-Key`.
- **سجلات JSON**: `logs\kashif.service.jsonl` بتدوير تلقائي. **سجل التغييرات**: `CHANGELOG.md`.
