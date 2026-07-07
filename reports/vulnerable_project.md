# تقرير كاشف

- الجذر: `C:\Projects\kashif\examples\vulnerable_project`
- الملفات: `2`
- الملاحظات: `7`
- الشدّات: `{'critical': 2, 'high': 5}`

## أعلى المخاطر

- **critical / سر مضمّن في الكود** `app.py:5` `CWE-798` — `API_KEY = "sk_test_1234567890abcdef"`
- **critical / subprocess مع shell=True** `app.py:9` `CWE-78` — `subprocess.check_output(command, shell=True)`
- **high / تحميل pickle غير آمن** `app.py:13` `CWE-502` — `pickle.loads(raw)`
- **high / SQL مبني بسلاسل** `app.py:17` `CWE-89` — `SELECT * FROM users WHERE id = " +`
- **high / تنفيذ نظام مباشر** `app.py:22` `CWE-78` — `os.system("echo cleanup")`
- **high / سلسلة مشبوهة داخل ثنائي** `blob.bin` `CWE-200` — `powershell`
- **high / سلسلة مشبوهة داخل ثنائي** `blob.bin` `CWE-200` — `password`

## خريطة الملفات

- `app.py` py size=366 lines=22 symbols=4
- `blob.bin` binary size=52 lines=0 entropy=4.169 magic=PE/Windows executable
