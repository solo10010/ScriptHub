<p align="center">
  <img src="https://raw.githubusercontent.com/solo10010/ScriptHub/main/ScriptHub.png" alt="ScriptHub Logo" width="800">
</p>

🚀 **ScriptHub: Коллекция Быстрых Скриптов для Серверов**

Добро пожаловать в **ScriptHub** — вашу центральную точку для моментального доступа к полезным скриптам, готовым к выполнению прямо на ваших серверах. Эта коллекция предоставляет скрипты, доступные по URL на gh-pages, предназначенные для мгновенного запуска без необходимости сохранения на диске. 🌐💻

**Примеры запуска скриптов с их аргументами**
```bash
curl -sSL https://solo10010.github.io/ScriptHub/script.sh | bash -s -- --help
```
```python
curl -sSL https://solo10010.github.io/ScriptHub/script.py | python3 - --help
```

**measure.py** - Данный скрипт Покажет измерение истинного потребления оперативной памяти и SWAP в Linux с группировкой по пользователям или приложениям

**Аргументы:** - нету

**OS** - Linux

```bash
curl -sSL https://solo10010.github.io/ScriptHub/measure.py | python3
```

---

**ps_mem.py** - Утилита для точного отчета об использовании основной памяти процессами в системе, можно использовать для расчета max_children, и некоторых лругих параметров которые отвечают за потребление оперативы.

**Источник** - https://github.com/pixelb/ps_mem

**Аргументы:** - -h|--help -p PID -s|--split-args -t|--total -w N -d|--discriminate-by-pid -S|--swap

**OS** - Linux

```bash
curl -sSL https://solo10010.github.io/ScriptHub/ps_mem.py | python3
```

---

**topdiskconsumer.sh** - Этот скрипт облегчает задачу определения того, что у вас занимает место на диске.

**Использование** - запустите его в любом каталоге файловой системы, которую необходимо диагностировать.

**Аргументы:** --help, -f, -p, -A, -l, -t, -o, -d, -m, -u, -f, -t, -v

**OS** - Linux

**Источник** - https://github.com/klazarsk/storagetoolkit/blob/main/topdiskconsumer

```bash
curl -sSL https://solo10010.github.io/ScriptHub/topdiskconsumer.sh | bash
```

---

**lbsa.sh** - (Linux Basic Security Audit script) — это базовый скрипт аудита конфигурации безопасности Linux-систем. Скрипт должен быть запущен из командной строки с привилегиям root или в идеале запускаться по расписанию на регулярной основе с помощью планировщика cron для систематической проверки изменений конфигурации. 

**Аргументы:** - нету

**OS** - Linux

```bash
curl -sSL https://solo10010.github.io/ScriptHub/lbsa.sh | bash
```

---

**tuning-mysql.sh** - Скрипт для начинающих по настройке производительности MySQL На основе: MySQLARd Версия: 1.99 Дата выпуска: 10.06.2018 

**Аргументы:** - нету

**OS** - Linux

```bash
curl -sSL https://solo10010.github.io/ScriptHub/tuning-mysql.sh | bash
```
---

**gtfonow.py** - Автоматическое повышение привилегий в системах unix путем использования неправильно настроенных двоичных файлов setuid/setgid, возможностей и разрешений sudo. Разработан для CTF, но также применим и в реальных пентестах.

**Аргументы:** - нету

**OS** - Linux

```bash
curl -sSL https://solo10010.github.io/ScriptHub/gtfonow.py | python3
```
---

**LinPEAS.sh** - это скрипт, который ищет возможные пути повышения привилегий на хостах Linux/Unix*/MacOS. Проверки описаны на https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist.

**Аргументы:** - нету

**OS** - Linux

```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

