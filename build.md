# Сборка (build) — команды

Ниже собраны команды для повторяемой сборки EXE (сервер и атакующий) на Windows.

## 1) Подготовка окружения

### Вариант A: через готовый батник (cmd)

```bat
setup_env.bat
```

### Вариант B: вручную (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 2) Запуск без сборки (для проверки перед EXE)

```powershell
python .\gui_server.py
python .\gui_attacker.py
```

CLI-режим:

```powershell
python .\run_server.py
python .\run_attacker.py -t 127.0.0.1 -p 8443
```

## 3) Сборка EXE через build_exe.py (рекомендуется)

Скрипт сборки уже настроен под проект и включает необходимые данные (common/, profiles/, databases/, tools/ если есть).

### Собрать оба агента

```powershell
python .\build_exe.py
```

### Собрать только сервер

```powershell
python .\build_exe.py --server
```

### Собрать только атакующего

```powershell
python .\build_exe.py --attacker
```

### Собрать “единый exe” (onefile)

```powershell
python .\build_exe.py --onefile
python .\build_exe.py --server --onefile
python .\build_exe.py --attacker --onefile
```

## 4) Где искать результат сборки

### onedir (по умолчанию)

- Сервер: `.\dist\SecurityServer\SecurityServer.exe`
- Атакующий: `.\dist_attacker\SecurityAttacker\SecurityAttacker.exe`

### onefile (--onefile)

- Сервер: `.\dist\SecurityServer.exe`
- Атакующий: `.\dist_attacker\SecurityAttacker.exe`

## 5) Очистка артефактов сборки

PowerShell:

```powershell
Remove-Item -Recurse -Force .\build, .\dist, .\dist_attacker -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .\__pycache__ -ErrorAction SilentlyContinue
```

cmd:

```bat
rmdir /s /q build
rmdir /s /q dist
rmdir /s /q dist_attacker
```

## 6) Ручной PyInstaller (если нужно без build_exe.py)

Важно: на Windows разделитель в --add-data — `;` (точка с запятой).

### Сервер (onefile)

```powershell
python -m PyInstaller `
  --name SecurityServer `
  --onefile `
  --windowed `
  --noconfirm `
  --clean `
  --add-data "common;common" `
  --add-data "server;server" `
  --add-data "databases;databases" `
  --add-data "profiles;profiles" `
  gui_server.py
```

### Атакующий (onefile)

```powershell
python -m PyInstaller `
  --name SecurityAttacker `
  --onefile `
  --windowed `
  --noconfirm `
  --clean `
  --add-data "common;common" `
  --add-data "attacker;attacker" `
  --add-data "databases;databases" `
  --add-data "profiles;profiles" `
  gui_attacker.py
```

