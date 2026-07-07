# تقرير كاشف

- الجذر: `C:\Projects\kashif`
- الملفات: `12`
- الملاحظات: `12`
- الشدّات: `{'high': 7, 'medium': 1, 'critical': 4}`

## أعلى المخاطر

- **critical / سر مضمّن في الكود** `examples/vulnerable_project/app.py:5` `CWE-798` — `API_KEY = "sk_test_1234567890abcdef"`
- **critical / subprocess مع shell=True** `examples/vulnerable_project/app.py:9` `CWE-78` — `subprocess.check_output(command, shell=True`
- **critical / وصول Docker socket** `kashif/scanner.py:24` `CWE-269` — `docker.sock`
- **critical / وصول Docker socket** `kashif/scanner.py:85` `CWE-269` — `docker.sock`
- **high / تحميل pickle غير آمن** `examples/vulnerable_project/app.py:13` `CWE-502` — `pickle.loads(`
- **high / SQL مبني بسلاسل** `examples/vulnerable_project/app.py:17` `CWE-89` — `SELECT * FROM users WHERE id = " +`
- **high / تنفيذ نظام مباشر** `examples/vulnerable_project/app.py:22` `CWE-78` — `os.system(`
- **high / سلسلة مشبوهة داخل ثنائي** `examples/vulnerable_project/blob.bin` `CWE-200` — `powershell`
- **high / سلسلة مشبوهة داخل ثنائي** `examples/vulnerable_project/blob.bin` `CWE-200` — `password`
- **high / SQL مبني بسلاسل** `kashif/datasets.py:86` `CWE-89` — `update(cwes) total += 1 if total >= limit: break start +`
- **high / SQL مبني بسلاسل** `kashif/scanner.py:20` `CWE-89` — `SELECT|INSERT|UPDATE|DELETE).{0,120}(\+|%`
- **medium / تعطيل تحقق TLS** `kashif/scanner.py:21` `CWE-295` — `verify=False`

## خريطة الملفات

- `.gitignore` binary size=38 lines=0 entropy=3.873 magic=5f5f707963616368
- `pyproject.toml` toml size=222 lines=10
- `README.md` md size=1667 lines=38
- `kashif/cli.py` py size=2222 lines=61 symbols=4
- `kashif/datasets.py` py size=3690 lines=98 symbols=5
- `kashif/models.py` py size=986 lines=48 symbols=6
- `kashif/reports.py` py size=2067 lines=50 symbols=2
- `kashif/scanner.py` py size=6521 lines=128 symbols=7
- `kashif/__init__.py` py size=22 lines=1
- `tests/test_kashif.py` py size=869 lines=25 symbols=3
- `examples/vulnerable_project/app.py` py size=366 lines=22 symbols=4
- `examples/vulnerable_project/blob.bin` binary size=52 lines=0 entropy=4.169 magic=PE/Windows executable
