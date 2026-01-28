import base64
import ctypes
from ctypes import wintypes
import json
import os
import subprocess
import re
import tkinter as tk
from tkinter import ttk, messagebox

# ==========================
# Конфигурация доменов
# ==========================

DOMAIN_CONFIGS = [
    {
        "name": "pak-cspmz",
        "label": "Создавать в pak-cspmz",
        "server": "dc03.pak-cspmz.ru",
        "ou_dn": "OU=omg,OU=csp,OU=Users,OU=csp,DC=pak-cspmz,DC=ru",
        "upn_suffix": "@pak-cspmz.ru",
        "email_suffix": "@cspfmba.ru",
    },
    {
        "name": "omg-cspfmba",
        "label": "Создавать в omg.cspfmba",
        "server": "DC22.omg.cspfmba.ru",
        "ou_dn": "OU=Institute of Synthetic Biology and Genetic Engineering,DC=omg,DC=cspfmba,DC=ru",
        "upn_suffix": "@omg.cspfmba.ru",
        "email_suffix": "@cspfmba.ru",
    },
]

COMPANY_NAME = "ФГБУ «ЦСП» ФМБА России"

CONFIG_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "ADHelper")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
CONFIG_PASSWORD_KEY = "password_token"

ADDRESS_CHOICES = [
    "ул. Щукинская, дом 5, стр.5",
    "ул. Погодинская, д. 10, стр.2",
    "ул. Погодинская, д. 10, стр.1",
]

# Детали адреса для AD (атрибуты: l, postalCode, postOfficeBox, st, c)
ADDRESS_DETAILS = {
    "ул. Щукинская, дом 5, стр.5": {
        "pobox": "Москва",        # postOfficeBox
        "city": "Москва",         # l
        "state": "Москва",        # st
        "postal_code": "123182",  # postalCode
        "country": "RU",          # c
    },
    "ул. Погодинская, д. 10, стр.2": {
        "pobox": "Москва",
        "city": "Москва",
        "state": "Москва",
        "postal_code": "119121",
        "country": "RU",
    },
        "ул. Погодинская, д. 10, стр.1": {
        "pobox": "Москва",
        "city": "Москва",
        "state": "Москва",
        "postal_code": "119121",
        "country": "RU",
    },
}

# Логика section для omg
OMG_SECTION_SKIP_DEPARTMENTS = {
    "отдел научно-технического и методического обеспечения",
    "отдел редакционно-издательской деятельности",
}

OMG_MANAGEMENT_SECTION = {
    "управление организации и проведения исследований",
    "управление цифровых систем и биоинформатики",
    "управление экспериментальной биотехнологии и генной инженерии",
}

OMG_DIVISION_VALUE = "институт синтетической биологии и генной инженерии"


# ==========================
# Вспомогательные функции
# ==========================

class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _blob_from_bytes(data: bytes) -> _DataBlob:
    buffer = ctypes.create_string_buffer(data)
    blob = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    blob._buffer = buffer
    return blob


def _bytes_from_blob(blob: _DataBlob) -> bytes:
    return ctypes.string_at(blob.pbData, blob.cbData)


def _crypt_protect(data: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    blob_in = _blob_from_bytes(data)
    blob_out = _DataBlob()
    if not crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(blob_out),
    ):
        raise ctypes.WinError()
    try:
        return _bytes_from_blob(blob_out)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def _crypt_unprotect(data: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    blob_in = _blob_from_bytes(data)
    blob_out = _DataBlob()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(blob_out),
    ):
        raise ctypes.WinError()
    try:
        return _bytes_from_blob(blob_out)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def encrypt_password(plain: str) -> str:
    if not plain:
        return ""
    raw = plain.encode("utf-16-le")
    protected = _crypt_protect(raw)
    return base64.b64encode(protected).decode("ascii")


def decrypt_password(token: str) -> str:
    if not token:
        return ""
    protected = base64.b64decode(token)
    raw = _crypt_unprotect(protected)
    return raw.decode("utf-16-le")


def load_password_token() -> str:
    if not os.path.exists(CONFIG_PATH):
        return ""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return ""
    return data.get(CONFIG_PASSWORD_KEY, "") or ""


def save_password_token(token: str) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    data = {CONFIG_PASSWORD_KEY: token}
    with open(CONFIG_PATH, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)

def run_powershell(command: str) -> subprocess.CompletedProcess:
    full_cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", command,
    ]
    return subprocess.run(full_cmd, capture_output=True, text=True, errors="replace")

def translit_gost(text: str) -> str:
    mapping = {
        "а": "a",  "б": "b",  "в": "v",   "г": "g",   "д": "d",
        "е": "e",  "ё": "yo", "ж": "zh",  "з": "z",   "и": "i",
        "й": "y",
        "к": "k",  "л": "l",  "м": "m",   "н": "n",
        "о": "o",  "п": "p",  "р": "r",   "с": "s",   "т": "t",
        "у": "u",  "ф": "f",  "х": "kh",  "ц": "ts",  "ч": "ch",
        "ш": "sh", "щ": "shch", "ъ": None, "ы": "y",  "ь": None,
        "э": "e",  "ю": "yu", "я": "ya",
    }
    result = []
    for ch in text.lower():
        if ch in mapping:
            val = mapping[ch]
            if val:
                result.append(val)
        elif ch.isalnum():
            result.append(ch)
        else:
            continue
    return "".join(result)

def parse_bool(value: str) -> bool:
    value = value.strip().lower()
    return value in ("да", "yes", "y", "true", "1")

def normalize_phone(raw: str) -> str:
    """
    +7(917)561-44-55 -> 89175614455
    """
    if not raw:
        return ""
    digits = re.sub(r"\D", "", raw)
    if not digits:
        return ""
    if digits[0] == "7" and len(digits) >= 11:
        return "8" + digits[1:11]
    if digits[0] == "8" and len(digits) >= 11:
        return digits[:11]
    if len(digits) == 10:
        return "8" + digits
    return digits

def parse_form(text: str) -> dict:
    field_map = {
        "Фамилия": "last_name",
        "Имя": "first_name",
        "Отчество": "middle_name",
        "Есть ли у вас фотография сотрудника": "has_photo",
        "Руководитель": "manager_name",
        "Управление": "management",
        "Отдел": "department",
        "Должность сотрудника": "title",
        "Дата выхода сотрудника": "start_date",
        "Режим работы сотрудника": "work_mode",
        "Номер кабинета": "office_room",
        "Предоставить электронный почтовый ящик для сотрудника": "need_mail",
        "Предоставить внутренний телефонный номер для сотрудника": "need_internal_phone",
        "Номер сотового телефона для переадресации": "mobile_phone",
        "Оборудование необходимое сотруднику": "equipment",
        "Операционная система для ноутбука в офисе": "office_os",
        "Предоставить доступ к серверам": "need_servers_access",
        "Предоставить доступ к папкам": "need_folders_access",
        "Примечание": "notes",
    }

    data = {v: None for v in field_map.values()}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        line = re.sub(r"^\d+\)\s*", "", line)
        if " :" in line:
            key_part, value_part = line.split(" :", 1)
        elif ":" in line:
            key_part, value_part = line.split(":", 1)
        else:
            continue
        key_part = key_part.strip()
        value_part = value_part.strip()

        matched_key = None
        for label, internal_key in field_map.items():
            if key_part.lower().startswith(label.lower()):
                matched_key = internal_key
                break

        if not matched_key:
            continue

        if matched_key in ("need_mail", "need_internal_phone", "has_photo",
                           "need_servers_access", "need_folders_access"):
            data[matched_key] = parse_bool(value_part)
        else:
            data[matched_key] = value_part

    return data

def user_exists_in_domain(server: str, sam: str) -> bool:
    ps = (
        "Import-Module ActiveDirectory; "
        f"$u = Get-ADUser -Server {server} "
        f"-Filter \"SamAccountName -eq '{sam}'\" -ErrorAction SilentlyContinue; "
        "if ($u) { '1' } else { '0' };"
    )
    proc = run_powershell(ps)
    if proc.returncode != 0:
        return False
    output = (proc.stdout or "").strip()
    return output == "1"

def user_exists_in_any_domain(sam: str) -> bool:
    return any(user_exists_in_domain(cfg["server"], sam) for cfg in DOMAIN_CONFIGS)

def generate_samaccount_name(first_name: str, last_name: str) -> str:
    first_name = first_name.strip()
    last_name = last_name.strip()

    base = translit_gost(first_name[:1]) + translit_gost(last_name)
    candidates = [base]

    if len(first_name) > 1:
        two_letters = translit_gost(first_name[:2]) + translit_gost(last_name)
        if two_letters != base:
            candidates.append(two_letters)

    suffix = 2
    while True:
        for cand in candidates:
            if not user_exists_in_any_domain(cand):
                return cand
        candidates.append(f"{base}{suffix}")
        suffix += 1

def get_ad_department(parsed: dict) -> str:
    raw_dep = parsed.get("department")
    raw_mgmt = parsed.get("management")

    source = None
    if raw_dep:
        source = raw_dep
    elif raw_mgmt:
        source = raw_mgmt
    else:
        return ""

    parts = [p.strip() for p in str(source).split("/") if p.strip()]
    if parts:
        dep = parts[-1]
    else:
        dep = str(source).strip()

    dep = dep.lower()
    return dep[:64]

def get_omg_section(parsed: dict) -> str:
    """
    section для omg, максимум 32 символа
    """
    raw_dep = (parsed.get("department") or "").strip().lower()
    raw_mgmt = (parsed.get("management") or "").strip().lower()

    if raw_dep and raw_dep in OMG_SECTION_SKIP_DEPARTMENTS:
        return ""

    if raw_mgmt and raw_mgmt in OMG_MANAGEMENT_SECTION:
        if raw_dep:
            parts = [p.strip() for p in raw_dep.split("/") if p.strip()]
            if parts:
                sec = parts[-1]
            else:
                sec = raw_dep
        else:
            sec = raw_mgmt
        return sec[:32]

    return ""

def get_address_details(address: str) -> dict:
    base = {
        "pobox": "",
        "city": "",
        "state": "",
        "postal_code": "",
        "country": "",
    }
    if not address:
        return base
    meta = ADDRESS_DETAILS.get(address)
    if not meta:
        return base
    res = base.copy()
    res.update(meta)
    return res

def manager_exists_for_domain(cfg: dict, manager_name: str) -> bool:
    """
    Проверяем, есть ли руководитель в ЭТОМ домене (без fallback).
    """
    name = (manager_name or "").strip()
    if not name:
        return False
    name_ps = name.replace("'", "''")

    ps = (
        "Import-Module ActiveDirectory; "
        f"$name = '{name_ps}'; "
        f"$mgr = Get-ADUser -Server {cfg['server']} "
        "-Filter \"DisplayName -like '*$name*'\" "
        "-ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if ($mgr) { '1' } else { '0' }"
    )

    proc = run_powershell(ps)
    if proc.returncode != 0:
        return False
    return (proc.stdout or "").strip() == "1"

def user_exists_in_domain(cfg: dict, sam: str, upn: str) -> tuple[bool, str]:
    """
    Проверяем наличие пользователя в домене по SamAccountName/UPN.
    """
    sam_ps = (sam or "").replace("'", "''")
    upn_ps = (upn or "").replace("'", "''")

    ps = (
        "Import-Module ActiveDirectory; "
        f"$sam = '{sam_ps}'; "
        f"$upn = '{upn_ps}'; "
        f"$user = Get-ADUser -Server {cfg['server']} "
        "-Filter \"SamAccountName -eq '$sam' -or UserPrincipalName -eq '$upn'\" "
        "-Properties SamAccountName, UserPrincipalName, DisplayName "
        "-ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if ($user) { "
        "  $user.SamAccountName + '|' + $user.UserPrincipalName + '|' + $user.DisplayName "
        "} "
    )

    proc = run_powershell(ps)
    if proc.returncode != 0:
        return False, ""
    data = (proc.stdout or "").strip()
    if not data:
        return False, ""
    return True, data

# ==========================
# Создание пользователя
# ==========================

def create_user_in_domain(
    cfg: dict,
    sam: str,
    parsed: dict,
    address: str,
    manager_name: str = "",
    password_plain: str = "",
    dry_run: bool = False,
) -> tuple[str, bool]:
    last_name = parsed.get("last_name") or ""
    first_name = parsed.get("first_name") or ""
    middle_name = parsed.get("middle_name") or ""

    title_raw = parsed.get("title") or ""
    title = title_raw.strip().lower()

    department = get_ad_department(parsed)
    office_room = (parsed.get("office_room") or "").strip()
    need_mail = parsed.get("need_mail") or False

    raw_mobile = parsed.get("mobile_phone") or ""
    mobile = normalize_phone(raw_mobile) if raw_mobile else ""

    display_name = " ".join(x for x in [last_name, first_name, middle_name] if x)

    upn = sam + cfg["upn_suffix"]
    email = sam + cfg["email_suffix"] if need_mail else ""

    description = title

    is_omg = (cfg["name"] == "omg-cspfmba")
    division = OMG_DIVISION_VALUE if is_omg else ""
    otp_mobile = mobile if is_omg and mobile else ""
    section = get_omg_section(parsed) if is_omg else ""

    addr_meta = get_address_details(address)
    pobox = addr_meta["pobox"]
    city = addr_meta["city"]
    state = addr_meta["state"]
    postal_code = addr_meta["postal_code"]
    country = addr_meta["country"]  # RU

    mgr_name_value = (manager_name or "").strip()
    mgr_name_escaped = mgr_name_value.replace("'", "''")

    password_escaped = password_plain.replace("'", "''")

    ps_lines = [
        "Import-Module ActiveDirectory",
        f"$securePassword = ConvertTo-SecureString '{password_escaped}' -AsPlainText -Force",
        f"$name = '{display_name}'",
        f"$givenName = '{first_name}'",
        f"$surname = '{last_name}'",
        f"$sam = '{sam}'",
        f"$upn = '{upn}'",
        f"$title = '{title}'",
        f"$department = '{department}'",
        f"$company = '{COMPANY_NAME}'",
        f"$office = '{office_room}'",
        f"$street = '{address}'",
        f"$description = '{description}'",
        f"$mobile = '{mobile}'",
        f"$mail = '{email}'",
        f"$mgrName = '{mgr_name_escaped}'",
        f"$pobox = '{pobox}'",
        f"$city = '{city}'",
        f"$state = '{state}'",
        f"$postalCode = '{postal_code}'",
        f"$country = '{country}'",
    ]

    if is_omg:
        ps_lines.append(f"$division = '{division}'")
        ps_lines.append(f"$otpMobile = '{otp_mobile}'")
        ps_lines.append(f"$section = '{section}'")

    new_aduser_cmd = (
        "New-ADUser "
        f"-Server {cfg['server']} "
        f"-Path '{cfg['ou_dn']}' "
        "-Name $name "
        "-GivenName $givenName "
        "-Surname $surname "
        "-SamAccountName $sam "
        "-UserPrincipalName $upn "
        "-DisplayName $name "
    )

    if title:
        new_aduser_cmd += "-Title $title "
    if department:
        new_aduser_cmd += "-Department $department "
    if COMPANY_NAME:
        new_aduser_cmd += "-Company $company "
    if office_room:
        new_aduser_cmd += "-Office $office "
    if email:
        new_aduser_cmd += "-EmailAddress $mail "

    # Адресные поля
    if pobox:
        new_aduser_cmd += "-POBox $pobox "
    if city:
        new_aduser_cmd += "-City $city "
    if state:
        new_aduser_cmd += "-State $state "
    if postal_code:
        new_aduser_cmd += "-PostalCode $postalCode "
    if country:
        new_aduser_cmd += "-Country $country "

    # В omg mobile не заполняем, только otpMobile
    if mobile and not is_omg:
        new_aduser_cmd += "-MobilePhone $mobile "

    if address:
        new_aduser_cmd += "-StreetAddress $street "
    if description:
        new_aduser_cmd += "-Description $description "

    if is_omg and division:
        new_aduser_cmd += "-Division $division "

    new_aduser_cmd += "-AccountPassword $securePassword -Enabled:$false "

    other_attrs_parts = []
    if is_omg:
        if otp_mobile:
            other_attrs_parts.append("'otpMobile'=$otpMobile")
        if section:
            other_attrs_parts.append("'section'=$section")

    if other_attrs_parts:
        new_aduser_cmd += " -OtherAttributes @{" + "; ".join(other_attrs_parts) + "}"

    ps_lines.append(new_aduser_cmd)

    # Post-обработка Manager — только в СВОЁМ домене, без fallback
    post_mgr_cmd = (
        "if ($mgrName -ne '') { "
        f"$mgr = Get-ADUser -Server {cfg['server']} "
        "-Filter \"DisplayName -like '*$mgrName*'\" "
        "-ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if ($mgr) { "
        f"  Set-ADUser -Server {cfg['server']} -Identity $sam -Manager $mgr.DistinguishedName "
        "} "
        "}"
    )

    ps_lines.append(post_mgr_cmd)

    ps_script = "; ".join(ps_lines)

    if dry_run:
        ps_script_safe = ps_script.replace(password_escaped, "<скрыто>")
        return f"[{cfg['name']}] DRY RUN PowerShell:\n{ps_script_safe}\n", False

    proc = run_powershell(ps_script)
    stderr = proc.stderr or ""
    stdout = proc.stdout or ""
    success = proc.returncode == 0

    log_lines = [f"[{cfg['name']}] New-ADUser/Set-ADUser выполнены, код {proc.returncode}"]

    # Человеческие расшифровки частых ошибок
    if "Server:8305" in stderr:
        log_lines.append(
            "Пояснение: AD вернул ошибку 8305 – объект с таким именем уже существует "
            "в целевой OU. Скорее всего, в этом контейнере уже есть пользователь "
            "с таким же ФИО (Name/CN), поэтому новый пользователь НЕ был создан."
        )

    if "ADIdentityNotFoundException" in stderr and "Set-ADUser" in stderr:
        log_lines.append(
            "Пояснение: не удалось установить руководителя (атрибут Manager) – "
            "объект руководителя не найден или недоступен в этом домене."
        )

    if stdout:
        log_lines.append("STDOUT:")
        log_lines.append(stdout)
    if stderr:
        log_lines.append("STDERR:")
        log_lines.append(stderr)

    return "\n".join(log_lines) + "\n", success


def update_user_in_domain(
    cfg: dict,
    sam: str,
    title: str,
    department: str,
    office_room: str,
    mobile_raw: str,
    telephone_raw: str,
    address: str,
    manager_name: str,
    need_mail: bool,
) -> tuple[str, bool]:
    title = (title or "").strip().lower()
    department = (department or "").strip().lower()
    office_room = (office_room or "").strip()
    mobile = normalize_phone(mobile_raw) if mobile_raw else ""
    telephone = normalize_phone(telephone_raw) if telephone_raw else ""

    addr_meta = get_address_details(address)
    pobox = addr_meta["pobox"]
    city = addr_meta["city"]
    state = addr_meta["state"]
    postal_code = addr_meta["postal_code"]
    country = addr_meta["country"]

    manager_name = (manager_name or "").strip()
    manager_escaped = manager_name.replace("'", "''")

    email = sam + cfg["email_suffix"] if need_mail else ""

    is_omg = (cfg["name"] == "omg-cspfmba")
    otp_mobile = mobile if is_omg and mobile else ""

    ps_lines = [
        "Import-Module ActiveDirectory",
        f"$sam = '{sam}'",
        f"$title = '{title}'",
        f"$department = '{department}'",
        f"$office = '{office_room}'",
        f"$street = '{address}'",
        f"$mobile = '{mobile}'",
        f"$telephone = '{telephone}'",
        f"$mail = '{email}'",
        f"$mgrName = '{manager_escaped}'",
        f"$pobox = '{pobox}'",
        f"$city = '{city}'",
        f"$state = '{state}'",
        f"$postalCode = '{postal_code}'",
        f"$country = '{country}'",
    ]

    if is_omg:
        ps_lines.append(f"$otpMobile = '{otp_mobile}'")

    clear_parts = []
    if not need_mail:
        clear_parts.append("'mail'")
    if not title:
        clear_parts.append("'title'")
    if not department:
        clear_parts.append("'department'")
    if not office_room:
        clear_parts.append("'physicalDeliveryOfficeName'")
    if not address:
        clear_parts.append("'streetAddress'")
    if not pobox:
        clear_parts.append("'postOfficeBox'")
    if not city:
        clear_parts.append("'l'")
    if not state:
        clear_parts.append("'st'")
    if not postal_code:
        clear_parts.append("'postalCode'")
    if not country:
        clear_parts.append("'c'")
    if not mobile:
        clear_parts.append("'mobile'")
    if not telephone:
        clear_parts.append("'telephoneNumber'")
    if not manager_name:
        clear_parts.append("'manager'")

    set_cmd = f"Set-ADUser -Server {cfg['server']} -Identity $sam "
    if title:
        set_cmd += "-Title $title "
    if department:
        set_cmd += "-Department $department "
    if office_room:
        set_cmd += "-Office $office "
    if address:
        set_cmd += "-StreetAddress $street "
    if pobox:
        set_cmd += "-POBox $pobox "
    if city:
        set_cmd += "-City $city "
    if state:
        set_cmd += "-State $state "
    if postal_code:
        set_cmd += "-PostalCode $postalCode "
    if country:
        set_cmd += "-Country $country "
    if need_mail and email:
        set_cmd += "-EmailAddress $mail "
    if mobile and not is_omg:
        set_cmd += "-MobilePhone $mobile "
    if telephone:
        set_cmd += "-OfficePhone $telephone "
    if clear_parts:
        set_cmd += "-Clear @(" + ", ".join(clear_parts) + ") "

    ps_lines.append(set_cmd)

    replace_parts = []
    if is_omg and otp_mobile:
        replace_parts.append("'otpMobile'=$otpMobile")

    if replace_parts:
        ps_lines.append("Set-ADUser -Server " + cfg["server"] + " -Identity $sam "
                        "-Replace @{" + "; ".join(replace_parts) + "}")

    post_mgr_cmd = (
        "if ($mgrName -ne '') { "
        f"$mgr = Get-ADUser -Server {cfg['server']} "
        "-Filter \"DisplayName -like '*$mgrName*'\" "
        "-ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if ($mgr) { "
        f"  Set-ADUser -Server {cfg['server']} -Identity $sam -Manager $mgr.DistinguishedName "
        "} "
        "}"
    )
    ps_lines.append(post_mgr_cmd)

    ps_script = "; ".join(ps_lines)
    proc = run_powershell(ps_script)
    stderr = proc.stderr or ""
    stdout = proc.stdout or ""
    success = proc.returncode == 0

    log_lines = [f"[{cfg['name']}] Set-ADUser выполнен, код {proc.returncode}"]
    if "ADIdentityNotFoundException" in stderr and "Set-ADUser" in stderr:
        log_lines.append(
            "Пояснение: не удалось обновить руководителя – "
            "объект руководителя не найден или недоступен в этом домене."
        )
    if stdout:
        log_lines.append("STDOUT:")
        log_lines.append(stdout)
    if stderr:
        log_lines.append("STDERR:")
        log_lines.append(stderr)

    return "\n".join(log_lines) + "\n", success


# ==========================
# GUI
# ==========================

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Создание пользователя в AD из заявки")
        self.geometry("980x900")

        self.domain_vars = {}
        self.password_token = load_password_token()
        self.history_entries = []
        self.selected_history_index = None
        self._build_widgets()

    def _build_widgets(self):
        frm_top = ttk.Frame(self)
        frm_top.pack(fill="both", expand=True, padx=10, pady=10)

        lbl = ttk.Label(frm_top, text="Вставьте текст заявки:")
        lbl.pack(anchor="w")

        self.txt_input = tk.Text(frm_top, height=20, wrap="word")
        self.txt_input.pack(fill="both", expand=True)

        frm_middle = ttk.Frame(self)
        frm_middle.pack(fill="x", padx=10, pady=5)

        frm_addr = ttk.Frame(frm_middle)
        frm_addr.pack(fill="x", pady=2)
        ttk.Label(frm_addr, text="Адрес офиса:").pack(side="left")
        self.address_var = tk.StringVar(value=ADDRESS_CHOICES[0])
        self.cmb_address = ttk.Combobox(
            frm_addr,
            textvariable=self.address_var,
            values=ADDRESS_CHOICES,
            state="readonly",
            width=40,
        )
        self.cmb_address.pack(side="left", padx=5)

        frm_password = ttk.Frame(frm_middle)
        frm_password.pack(fill="x", pady=2)

        ttk.Label(frm_password, text="Пароль по умолчанию:").pack(side="left")
        self.password_status_var = tk.StringVar()
        self._sync_password_status()
        ttk.Label(frm_password, textvariable=self.password_status_var).pack(side="left", padx=5)
        ttk.Button(
            frm_password,
            text="Изменить пароль",
            command=self._open_password_modal,
        ).pack(side="left")

        frm_flags = ttk.Frame(frm_middle)
        frm_flags.pack(fill="x", pady=2)

        self.dry_run_var = tk.BooleanVar(value=True)
        chk_dry = ttk.Checkbutton(
            frm_flags,
            text="Только разобрать (без создания пользователей)",
            variable=self.dry_run_var,
        )
        chk_dry.pack(side="left", padx=5)

        frm_domains = ttk.LabelFrame(self, text="Домены для создания пользователя")
        frm_domains.pack(fill="x", padx=10, pady=5)

        for cfg in DOMAIN_CONFIGS:
            var = tk.BooleanVar(value=True)
            self.domain_vars[cfg["name"]] = var
            chk = ttk.Checkbutton(
                frm_domains,
                text=cfg["label"],
                variable=var,
            )
            chk.pack(anchor="w", padx=5, pady=2)

        frm_btn = ttk.Frame(self)
        frm_btn.pack(fill="x", padx=10, pady=5)

        btn_run = ttk.Button(frm_btn, text="Разобрать и создать", command=self.on_run)
        btn_run.pack(side="left")

        frm_log = ttk.Frame(self)
        frm_log.pack(fill="both", expand=True, padx=10, pady=5)

        ttk.Label(frm_log, text="Лог:").pack(anchor="w")

        self.txt_log = tk.Text(frm_log, height=12, wrap="word", state="disabled")
        self.txt_log.pack(fill="both", expand=True)

        frm_history = ttk.LabelFrame(self, text="История созданных пользователей (текущий запуск)")
        frm_history.pack(fill="both", expand=False, padx=10, pady=5)

        frm_history_inner = ttk.Frame(frm_history)
        frm_history_inner.pack(fill="both", expand=True, padx=8, pady=8)

        frm_history_list = ttk.Frame(frm_history_inner)
        frm_history_list.pack(side="left", fill="both", expand=False)

        self.history_listbox = tk.Listbox(
            frm_history_list,
            height=8,
            width=40,
            exportselection=False,
        )
        self.history_listbox.pack(side="left", fill="both", expand=False)
        self.history_listbox.bind("<<ListboxSelect>>", self._on_history_select)

        history_scroll = ttk.Scrollbar(frm_history_list, orient="vertical", command=self.history_listbox.yview)
        history_scroll.pack(side="right", fill="y")
        self.history_listbox.configure(yscrollcommand=history_scroll.set)

        frm_history_editor = ttk.Frame(frm_history_inner)
        frm_history_editor.pack(side="left", fill="both", expand=True, padx=(12, 0))

        ttk.Label(frm_history_editor, text="Редактирование выбранного пользователя:").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 6)
        )

        self.edit_title_var = tk.StringVar()
        self.edit_department_var = tk.StringVar()
        self.edit_office_var = tk.StringVar()
        self.edit_mobile_var = tk.StringVar()
        self.edit_telephone_var = tk.StringVar()
        self.edit_manager_var = tk.StringVar()
        self.edit_need_mail_var = tk.BooleanVar()
        self.edit_address_var = tk.StringVar(value=ADDRESS_CHOICES[0])

        ttk.Label(frm_history_editor, text="Должность:").grid(row=1, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_history_editor, textvariable=self.edit_title_var, width=45).grid(
            row=1, column=1, sticky="w"
        )

        ttk.Label(frm_history_editor, text="Отдел (Department):").grid(row=2, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_history_editor, textvariable=self.edit_department_var, width=45).grid(
            row=2, column=1, sticky="w"
        )

        ttk.Label(frm_history_editor, text="Кабинет:").grid(row=3, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_history_editor, textvariable=self.edit_office_var, width=45).grid(
            row=3, column=1, sticky="w"
        )

        ttk.Label(frm_history_editor, text="Мобильный:").grid(row=4, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_history_editor, textvariable=self.edit_mobile_var, width=45).grid(
            row=4, column=1, sticky="w"
        )

        ttk.Label(frm_history_editor, text="Стационарный:").grid(row=5, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_history_editor, textvariable=self.edit_telephone_var, width=45).grid(
            row=5, column=1, sticky="w"
        )

        ttk.Label(frm_history_editor, text="Руководитель:").grid(row=6, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_history_editor, textvariable=self.edit_manager_var, width=45).grid(
            row=6, column=1, sticky="w"
        )

        ttk.Label(frm_history_editor, text="Адрес офиса:").grid(row=7, column=0, sticky="e", padx=(0, 6))
        ttk.Combobox(
            frm_history_editor,
            textvariable=self.edit_address_var,
            values=ADDRESS_CHOICES,
            state="readonly",
            width=42,
        ).grid(row=7, column=1, sticky="w")

        ttk.Checkbutton(
            frm_history_editor,
            text="Назначить корпоративную почту",
            variable=self.edit_need_mail_var,
        ).grid(row=8, column=1, sticky="w", pady=(4, 4))

        self.btn_save_changes = ttk.Button(
            frm_history_editor,
            text="Сохранить изменения",
            command=self._save_history_changes,
            state="disabled",
        )
        self.btn_save_changes.grid(row=9, column=1, sticky="w", pady=(6, 0))

    def log(self, msg: str):
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", msg + "\n")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _sync_password_status(self):
        if self.password_token:
            self.password_status_var.set("пароль задан")
        else:
            self.password_status_var.set("пароль не задан")

    def _open_password_modal(self):
        modal = tk.Toplevel(self)
        modal.title("Пароль по умолчанию")
        modal.resizable(False, False)
        modal.transient(self)
        modal.grab_set()

        ttk.Label(modal, text="Введите пароль:").pack(anchor="w", padx=10, pady=(10, 4))
        password_var = tk.StringVar()
        entry = ttk.Entry(modal, textvariable=password_var, show="*", width=32)
        entry.pack(padx=10, pady=4)
        entry.focus_set()

        btn_frame = ttk.Frame(modal)
        btn_frame.pack(padx=10, pady=(6, 10), fill="x")

        def save_and_close():
            password_plain = password_var.get().strip()
            if not password_plain:
                messagebox.showerror("Ошибка", "Введите пароль.")
                return
            token = encrypt_password(password_plain)
            save_password_token(token)
            self.password_token = token
            self._sync_password_status()
            modal.destroy()

        ttk.Button(btn_frame, text="Сохранить", command=save_and_close).pack(side="left")
        ttk.Button(btn_frame, text="Отмена", command=modal.destroy).pack(side="left", padx=5)

    def _on_history_select(self, _event=None):
        selection = self.history_listbox.curselection()
        if not selection:
            self.selected_history_index = None
            self.btn_save_changes.configure(state="disabled")
            return
        index = selection[0]
        self.selected_history_index = index
        entry = self.history_entries[index]
        self.edit_title_var.set(entry.get("title", ""))
        self.edit_department_var.set(entry.get("department", ""))
        self.edit_office_var.set(entry.get("office_room", ""))
        self.edit_mobile_var.set(entry.get("mobile_phone", ""))
        self.edit_telephone_var.set(entry.get("telephone_number", ""))
        self.edit_manager_var.set(entry.get("manager_name", ""))
        self.edit_need_mail_var.set(bool(entry.get("need_mail")))
        self.edit_address_var.set(entry.get("address") or ADDRESS_CHOICES[0])
        self.btn_save_changes.configure(state="normal")

    def _save_history_changes(self):
        if self.selected_history_index is None:
            messagebox.showerror("Ошибка", "Выберите пользователя из истории.")
            return
        entry = self.history_entries[self.selected_history_index]
        cfg = entry["cfg"]
        sam = entry["sam"]

        title = self.edit_title_var.get()
        department = self.edit_department_var.get()
        office_room = self.edit_office_var.get()
        mobile_raw = self.edit_mobile_var.get()
        telephone_raw = self.edit_telephone_var.get()
        manager_name = self.edit_manager_var.get()
        address = self.edit_address_var.get()
        need_mail = self.edit_need_mail_var.get()

        confirm = messagebox.askyesno(
            "Подтверждение",
            f"Обновить данные пользователя '{entry['display_name']}' "
            f"в домене '{cfg['name']}'?",
        )
        if not confirm:
            self.log("Обновление отменено пользователем.")
            return

        result_log, success = update_user_in_domain(
            cfg,
            sam,
            title=title,
            department=department,
            office_room=office_room,
            mobile_raw=mobile_raw,
            telephone_raw=telephone_raw,
            address=address,
            manager_name=manager_name,
            need_mail=need_mail,
        )
        self.log(result_log)
        if success:
            entry.update(
                {
                    "title": title,
                    "department": department,
                    "office_room": office_room,
                    "mobile_phone": mobile_raw,
                    "telephone_number": telephone_raw,
                    "manager_name": manager_name,
                    "address": address,
                    "need_mail": need_mail,
                }
            )
            self.log(f"[{cfg['name']}] Изменения для пользователя '{entry['display_name']}' сохранены.")
        else:
            self.log(f"[{cfg['name']}] Не удалось сохранить изменения для пользователя '{entry['display_name']}'.")

    def on_run(self):
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")

        raw_text = self.txt_input.get("1.0", "end").strip()
        if not raw_text:
            messagebox.showerror("Ошибка", "Текст заявки пуст.")
            return

        if not self.password_token:
            self.log("Пароль по умолчанию не задан.")
            messagebox.showerror("Ошибка", "Введите пароль по умолчанию.")
            return

        try:
            password_plain = decrypt_password(self.password_token)
        except Exception:
            self.log("Не удалось расшифровать пароль. Задайте пароль заново.")
            messagebox.showerror("Ошибка", "Не удалось расшифровать пароль. Задайте пароль заново.")
            return

        parsed = parse_form(raw_text)

        required_fields = ["last_name", "first_name"]
        missing = [f for f in required_fields if not parsed.get(f)]
        if missing:
            self.log(f"Не хватает обязательных полей: {', '.join(missing)}")
            messagebox.showerror("Ошибка", "Не хватает обязательных полей (фамилия/имя).")
            return

        selected_configs = [
            cfg for cfg in DOMAIN_CONFIGS
            if self.domain_vars.get(cfg["name"]) and self.domain_vars[cfg["name"]].get()
        ]
        if not selected_configs:
            self.log("Не выбран ни один домен для создания пользователя.")
            messagebox.showerror("Ошибка", "Выберите хотя бы один домен в блоке галочек.")
            return

        last_name = parsed.get("last_name", "")
        first_name = parsed.get("first_name", "")
        middle_name = parsed.get("middle_name", "")

        sam = generate_samaccount_name(first_name, last_name)
        display_name = " ".join(x for x in [last_name, first_name, middle_name] if x)

        address = self.address_var.get()
        addr_meta = get_address_details(address)

        title_raw = (parsed.get("title") or "").strip()
        title_norm = title_raw.lower()
        ad_department = get_ad_department(parsed)

        mobile_raw = parsed.get("mobile_phone") or ""
        mobile_norm = normalize_phone(mobile_raw) if mobile_raw else ""

        section_preview = get_omg_section(parsed)

        self.log("--- Разобранные данные заявки ---")
        self.log(f"ФИО: {display_name}")
        self.log(f"Логин (sAMAccountName): {sam}")
        self.log(f"Должность (title): '{title_norm}'")
        self.log(f"Управление (сырое): {parsed.get('management') or ''}")
        self.log(f"Отдел (сырое): {parsed.get('department') or ''}")
        self.log(f"Department (AD): '{ad_department}'")
        self.log(f"Кабинет (office): {parsed.get('office_room') or ''}")
        self.log(f"Мобильный исходный: {mobile_raw}")
        self.log(f"Мобильный нормализованный: {mobile_norm}")
        self.log(f"Нужна почта: {'Да' if parsed.get('need_mail') else 'Нет'}")
        self.log(f"Адрес офиса (StreetAddress): {address}")
        self.log(
            f"Адресные поля: POBox='{addr_meta['pobox']}', "
            f"City='{addr_meta['city']}', State='{addr_meta['state']}', "
            f"PostalCode='{addr_meta['postal_code']}', Country='{addr_meta['country']}'"
        )
        self.log("")

        self.log("--- Предпросмотр атрибутов для доменов ---")
        for cfg in selected_configs:
            upn_preview = sam + cfg["upn_suffix"]
            email_preview = sam + cfg["email_suffix"] if parsed.get("need_mail") else ""
            self.log(f"[{cfg['name']}] UPN: {upn_preview}, email: {email_preview or 'не задаётся'}")
            if cfg["name"] == "omg-cspfmba":
                self.log(
                    f"[{cfg['name']}] division: '{OMG_DIVISION_VALUE}', "
                    f"section: '{section_preview}', "
                    f"otpMobile: '{mobile_norm}' (MobilePhone не задаётся)"
                )
        self.log("")

        manager_name = parsed.get("manager_name") or ""
        if manager_name:
            self.log("--- Проверка наличия руководителя в ДАННОМ домене ---")
            for cfg in selected_configs:
                exists = manager_exists_for_domain(cfg, manager_name)
                if exists:
                    self.log(f"[{cfg['name']}] Руководитель '{manager_name}' найден в этом домене")
                else:
                    self.log(f"[{cfg['name']}] Руководитель '{manager_name}' НЕ найден в этом домене (Manager не будет установлен)")
            self.log("")
        else:
            self.log("Руководитель в заявке не указан.\n")

        configs_to_create = []
        for cfg in selected_configs:
            upn_preview = sam + cfg["upn_suffix"]
            exists, details = user_exists_in_domain(cfg, sam, upn_preview)
            if exists:
                sam_found, upn_found, display_found = (details.split("|") + ["", "", ""])[:3]
                self.log(
                    f"[{cfg['name']}] Пользователь уже существует в домене: "
                    f"Sam='{sam_found}', UPN='{upn_found}', DisplayName='{display_found}'. "
                    "Создание пропущено."
                )
            else:
                configs_to_create.append(cfg)

        if not configs_to_create:
            self.log("Создание пользователей остановлено: все выбранные домены уже содержат такого пользователя.")
            return

        dry_run = self.dry_run_var.get()
        dom_list_str = ", ".join(cfg["name"] for cfg in configs_to_create)

        if not dry_run:
            confirm = messagebox.askyesno(
                "Подтверждение",
                f"Создать пользователя '{display_name}' с логином '{sam}'\n"
                f"в доменах: {dom_list_str} ?",
            )
            if not confirm:
                self.log("Операция отменена пользователем.")
                return

        for cfg in configs_to_create:
            try:
                result_log, success = create_user_in_domain(
                    cfg,
                    sam,
                    parsed,
                    address,
                    manager_name=manager_name,
                    password_plain=password_plain,
                    dry_run=dry_run,
                )
                self.log(result_log)
                if success and not dry_run:
                    history_entry = {
                        "display_name": display_name,
                        "sam": sam,
                        "cfg": cfg,
                        "address": address,
                        "title": title_norm,
                        "department": ad_department,
                        "office_room": parsed.get("office_room") or "",
                        "mobile_phone": mobile_raw,
                        "telephone_number": "",
                        "manager_name": manager_name,
                        "need_mail": parsed.get("need_mail") or False,
                    }
                    self.history_entries.append(history_entry)
                    self.history_listbox.insert(
                        "end", f"{display_name}\\{cfg['name']}"
                    )
            except Exception as e:
                self.log(f"[{cfg['name']}] Ошибка: {e}")

        if dry_run:
            self.log("DRY RUN завершён. Пользователи фактически не создавались.")
        else:
            self.log("Создание пользователей завершено.")

if __name__ == "__main__":
    app = App()
    app.mainloop()

