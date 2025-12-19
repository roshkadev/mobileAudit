from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
from androguard.core.androconf import show_logging
from django.conf import settings
import logging, os, threading, hashlib, re, linecache, base64, urllib
from app.models import *
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import guess_lexer, guess_lexer_for_filename, PythonLexer
from datetime import datetime
from app.integration import *
from django.db.models import F

logger = logging.getLogger('app')

APK_PATH = ""
DECOMPILE_PATH = ""
_cached_root = {}

def set_hash_app(scan):
    if not scan.sha256:
        f = scan.apk.open('rb')
        sha1 = hashlib.sha1()
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        if f.multiple_chunks():
            for chunk in f.chunks():
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        else:
            md5.update(f.read())
            sha1.update(f.read())
            sha256.update(f.read())
        scan.md5 = md5.hexdigest()
        scan.sha1 = sha1.hexdigest()
        scan.sha256 = sha256.hexdigest()
        scan.file_size = scan.apk.size
        scan.save()
        f.close()
    return scan


def analyze_apk(task, scan_id):
    # Start the APK analysis
    global APK_PATH
    global DECOMPILE_PATH
    try:
        scan = Scan.objects.get(pk=scan_id)
        APK_PATH = settings.BASE_DIR + scan.apk.url
        DECOMPILE_PATH = os.path.splitext(APK_PATH)[0]
        scan.status = 'In Progress'
        scan.progress = 3
        scan.save()
        task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
        logger.debug(scan.status)
        a = APK(APK_PATH)
        scan = set_hash_app(scan)
        scan.status = 'Getting info of apk'
        scan.progress = 5
        scan.save()
        task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
        logger.debug(scan.status)
        scan = get_info_apk(a, scan)
        scan.status = 'Getting info of certificates'
        scan.progress = 10
        scan.save()
        task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
        logger.debug(scan.status)
        get_info_certificate(a, scan)
        if (settings.VIRUSTOTAL_ENABLED):
            scan.status = 'Getting info of VT'
            scan.progress = 15
            scan.save()
            task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
            logger.debug(scan.status)
            report = get_report_virus_total(scan, scan.sha256)
            if (not report and settings.VIRUSTOTAL_UPLOAD):
                scan.status = 'Upload to VT'
                scan.save()
                upload_virus_total(scan, APK_PATH, scan.sha256)
        scan.status = 'Decompiling'
        scan.progress = 20
        scan.save()
        task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
        logger.debug(scan.status)
        decompile_jadx()
        if (a.get_app_icon()):
            update_icon(scan, DECOMPILE_PATH + '/resources/' + a.get_app_icon())
        scan.status = 'Finding vulnerabilities'
        scan.progress = 40
        task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
        scan.save()
        logger.debug(scan.status)
        get_tree_dir(scan)
        scan.status = 'Finished'
        scan.progress = 100
        scan.finished_on = datetime.now()
        scan.save()
        task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
        logger.debug(scan.status)
    except Exception as e:
        scan.progress = 100
        scan.status = "Error"
        scan.finished_on = datetime.now()
        scan.save()
        task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
        logger.error(e)

def decompile_jadx():
    if (not os.path.isdir(DECOMPILE_PATH)):
        #execute jadx command
        os.system('jadx -d {} {}'.format(DECOMPILE_PATH, APK_PATH))
    # now we have sources/resources decompiled

def update_icon(scan, path):
    encoded_string = ''
    try:
        with open(path, 'rb') as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode("utf-8")
            scan.icon = encoded_string
            scan.save()
    except Exception as e:
        logger.error("no icon")  


def get_info_apk(a, scan):
    set_hash_app(scan)
    scan.package = a.get_package()
    scan.apk_name = a.get_app_name()
    scan.version_code = a.get_androidversion_code()
    scan.version_name = a.get_androidversion_name()
    scan.min_sdk_version = a.get_min_sdk_version()
    scan.max_sdk_version = a.get_max_sdk_version()
    scan.target_sdk_version = a.get_target_sdk_version()
    scan.effective_target_sdk_version = a.get_effective_target_sdk_version()
    scan.manifest = a.get_android_manifest_axml().get_xml()
    scan.save()

    permissions = a.get_permissions()
    for permission in permissions:
        try:
            permission_type = PermissionType.objects.get(name=permission)
        except Exception as e:
            permission_type = PermissionType(name=permission, type='Other', default_severity=Severity.HI)
            permission_type.save()
        p = Permission(scan=scan, permission=permission_type, severity=permission_type.default_severity)
        p.save()
    
    #Activities and their intent-filters
    for activity in a.get_activities():
        get_intent_filter(a, scan, 'activity', activity)

    #Services and their intent-filters:
    for service in a.get_services():
        get_intent_filter(a, scan, 'service', service)
    
    #Receivers and their intent-filters:
    for receiver in a.get_receivers():
        get_intent_filter(a, scan, 'receiver', receiver)
    
    #Providers and their intent-filters:
    for provider in a.get_providers():
        get_intent_filter(a, scan, 'provider', provider)
    
    return scan

def get_intent_filter(a, scan, type, name):
    component = Component(name=name, scan=scan, type=type)
    component.save()
    main = False
    launcher = False
    main_activity = False
    for action, intent_name in a.get_intent_filters(type, name).items():
        for intent in intent_name:
            if (action == 'action' and intent == 'android.intent.action.MAIN'):
                main = True
            if (action == 'category' and intent == 'android.intent.category.LAUNCHER'):
                launcher = True
            intent = IntentFilter(name=intent, scan=scan, action=action, component=component)
            intent.save()
    if (type == 'activity'):
        if (main and launcher):
            main_activity = True
        activity = Activity(name=name, scan=scan, main=main_activity)
        activity.save()


def get_info_certificate(a, scan):
    # first check if this APK is signed
    certificates = list()
    if a.is_signed():
        # Iterate over all certificates
        for cert in a.get_certificates():
            # Each cert is now a asn1crypt.x509.Certificate object
            # From the Certificate object, we can query stuff like:
            c = Certificate(
                scan=scan,
                version = '{}'.format('v1, v2, v3' if a.is_signed_v1() and a.is_signed_v2() and a.is_signed_v3() else 'v1' if a.is_signed_v1() else 'v2' if a.is_signed_v2() else 'v3'),
                sha1 = cert.sha1, #the sha1 fingerprint
                sha256 = cert.sha256,  # the sha256 fingerprint
                issuer = cert.issuer.human_friendly,  # issuer
                subject = cert.subject.human_friendly,  # subject, usually the same
                hash_algorithm = cert.hash_algo,  # hash algorithm
                signature_algorithm = cert.signature_algo,  # Signature algorithm
                serial_number = cert.serial_number,  # Serial number
                contents = cert.contents # The DER coded bytes of the certificate itself
            )
            c.save()
            certificates.append(c)
    return certificates


def get_tree_dir(scan):
    dir = DECOMPILE_PATH
    for dirpath, dirs, files in os.walk(dir): 
        for filename in files:
            fname = os.path.join(dirpath, filename)
            extension = os.path.splitext(fname)[1]
            if (extension == '.db' or extension == '.sqlite3' or extension =='.sql'):
                get_info_database(scan, fname)
            else:
                if (extension == '.java' or  extension == '.kt' or extension == '.xml'):
                    try:
                        prev_line = ''
                        i = 0
                        f = open(fname, mode="r", encoding="utf-8")
                        content = f.read()
                        f.close()
                        find_patterns(i + 1, prev_line, content, fname, dir, scan)
                    except Exception as e:
                        logger.error('ERROR {} {}'.format(e, fname))
                    if (filename == 'AndroidManifest.xml'):
                        get_info_file(scan, fname, dir)
                else:
                    get_info_file(scan, fname, dir)

def get_position(match):
    span = match.span()
    if span[0] == 0:
        span = list(span)
        span[0] = 1
    return tuple(span)

def get_match_lines(content, position):
    lines = ''
    c = 0
    end = False
    beginline = 0
    for i, line in enumerate(content.split('\n'), 1):
        c += len(line) + 1
        if c >= position[0] and c >= position[1] and not end: # only one line
            return (i, line)
        elif c >= position[0] and not end:
            # multiple lines
            beginline = i
            if (c >= position[1]):
                end = True
            lines += line + '\n'
        if c >= position[1] and end:
            # endline
            return (beginline, lines)


def find_patterns(i, prev_line, content, name, dir, scan):
    NS_ANDROID = "{http://schemas.android.com/apk/res/android}"
    
    # 1. IDENTIFICACIÓN DINÁMICA DEL PAQUETE RAÍZ
    if scan.id not in _cached_root:
        try:
            apk_obj = APK(scan.apk.path)
            manifest_xml = apk_obj.get_android_manifest_xml()
            injected_root = None
            
            # Buscar metadato inyectado por Gradle
            for meta in manifest_xml.findall(".//meta-data"):
                if meta.get(f"{NS_ANDROID}name") == "project_root_package":
                    injected_root = meta.get(f"{NS_ANDROID}value")
            
            if injected_root:
                _cached_root[scan.id] = injected_root.replace('.', '/')
                print(f"📦 [CONFIG] Root Package detectado: {_cached_root[scan.id]}", flush=True)
            else:
                # Fallback: Usar los primeros 3 niveles del package name
                parts = scan.package.split('.')
                _cached_root[scan.id] = "/".join(parts[:3]) if len(parts) >= 3 else "/".join(parts[:2])
                print(f"⚠️ [CONFIG] Fallback a Root Package: {_cached_root[scan.id]}", flush=True)
        except Exception as e:
            _cached_root[scan.id] = scan.package.replace('.', '/')
            print(f"❌ [ERROR] Fallo al leer APK: {e}", flush=True)

    root_package = _cached_root[scan.id]

    # 2. FILTROS DE EXCLUSIÓN AGRESIVOS (Human-made code only)
    is_internal = root_package in name
    
    # Solo procesamos código interno relevante
    if not name.endswith(('.java', '.kt', '.xml')) or not is_internal:
        return

    # Patrones para ignorar archivos generados y de configuración (DI)
    ignored_path_patterns = [
        '_Factory', '_Hilt', '_Singleton', '_MembersInjector', 
        'Dagger', 'Directions', 'Args', 'ViewBinding', 'BuildConfig',
        'NetworkModule', 'DataModule', 'AppModule'
    ]
    
    # Firmas de código de archivos generados o de configuración que disparan falsos positivos
    is_generated_content = any(attr in content for attr in [
        'implements Factory', 
        '@Module', 
        '@Provides', 
        'dagger.internal',
        'Preconditions.checkNotNullFromProvides'
    ])

    if any(p in name for p in ignored_path_patterns) or is_generated_content:
        # Si detectamos código generado o de inyección, lo saltamos
        return

    # 3. LIMPIEZA DE CONTENIDO PARA ANÁLISIS
    # Filtramos anotaciones y metadatos que causan falsos positivos (como @SerializedName)
    lines = content.split('\n')
    clean_lines = [l for l in lines if not l.strip().startswith(('@', 'import', 'package'))]
    analysis_content = "\n".join(clean_lines)

    # 4. MOTOR DE ESCANEO DE PATRONES
    patterns = Pattern.objects.filter(active=True)
    for p in patterns:
        regex = re.compile(p.pattern, re.MULTILINE | re.IGNORECASE)
        try:
            for match in regex.finditer(analysis_content):
                if match.group():
                    match_str = match.group().strip()[:500]
                    
                    # Obtención de atributos del modelo Pattern
                    p_name = getattr(p, 'name', getattr(p, 'default_name', 'Vulnerabilidad'))
                    p_sev = getattr(p, 'severity', getattr(p, 'default_severity', Severity.NO))
                    p_cwe = getattr(p, 'cwe', getattr(p, 'default_cwe', 'CWE-000'))
                    p_desc = getattr(p, 'description', getattr(p, 'default_description', ''))

                    # Persistencia del hallazgo
                    Finding.objects.create(
                        scan=scan,
                        path=name.replace(dir, ""),
                        name=p_name,
                        severity=p_sev,
                        description=p_desc,
                        line=match_str,
                        match=match_str,
                        status=Status.TD,
                        cwe=p_cwe,
                        user=scan.user
                    )
                    
                    # Actualización atómica en la base de datos
                    Scan.objects.filter(id=scan.id).update(findings=F('findings') + 1)
                    print(f"✅ [MATCH] {p_name} encontrado en: {name}", flush=True)
                    
        except Exception as e:
            print(f"❌ [ERROR REGEX] en {name}: {e}", flush=True)
            
         
def get_lines(finding='', path=''):
    formatter = HtmlFormatter(linenos=False, cssclass="source")
    if (finding):
        APK_PATH = settings.BASE_DIR + finding.scan.apk.url
        DECOMPILE_PATH = os.path.splitext(APK_PATH)[0]
        path = DECOMPILE_PATH + finding.path
    lines = []
    try:
        extension = os.path.splitext(path)[1]
        if (not extension == '.html' and not extension == '.js'):
            with open(path, encoding="utf-8") as f:
                for i, line in enumerate(f):
                    try:
                        if (i == 1):
                            lexer = guess_lexer_for_filename(path, line)
                        highlighted = highlight(line, lexer, formatter)
                        lines.append(highlighted)
                    except Exception as e:
                        if (line):
                            lines.append(line)
    except Exception as e:
        try:
            with open(path, encoding="utf-8") as f:
                for i, line in enumerate(f):
                    lines.append(line) 
        except Exception as e:
            logger.error(e)
    return lines


def get_info_file(scan, fname, dir):
    type = ''
    try:
        extension = os.path.splitext(fname)[1]
        if (extension == '.jpg' or fname == '.jpeg' or extension == '.png' or extension == '.gif' or extension == '.bmp' or extension == '.ico' or extension == '.svg'):
            type = 'image'
        elif (extension == '.mp4' or extension == '.mp3' or extension == '.avi' or extension == '.mkv' or extension == '.m4a'):
            type = 'media'
        elif (extension == '.xml'):
            type = 'xml'
        elif (extension == '.html'):
            type = 'html'
        elif (extension == '.properties'):
            type = 'properties'
        else:
            type = 'other'
        f = File(scan = scan, type = type, name = fname.replace(dir, ""), path = fname)
        f.save()
    except Exception as e:
        logger.error(e)

def get_info_database(scan, path):
    import sqlite3
    try:
        con = sqlite3.connect(path)
        # creating cursor
        cur = con.cursor()
        # reading all table names
        
        table_list = cur.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        try:
            for table in [_[0] for _ in table_list]:
                logger.error(table)
                try:
                    table_info_list = cur.execute("SELECT * FROM " + table)
                    # here is you table list
                    for table_info in [_[0] for _ in table_info_list]:
                        db = DatabaseInfo(scan=scan, table=table, info=table_info)
                        db.save()
                except Exception as e:
                    logger.error(e)
        except Exception as e:
            logger.error(e)
        # Be sure to close the connection
        con.close()
    except Exception as e:
        f = open(path)
        table_info = f.read() 
        db = DatabaseInfo(scan=scan, table='None', info=table_info)
        db.save()

def calculate_final_score(scan_id):
    """
    Calcula el Health Score (0-100) basado solo en hallazgos relevantes.
    """
    scan = Scan.objects.get(pk=scan_id)
    findings = Finding.objects.filter(scan=scan)
    
    # Pesos de penalización por severidad
    weights = {
        'CR': 25, # Critical
        'HI': 15, # High
        'ME': 5,  # Medium
        'LO': 1,  # Low
        'NO': 0   # None (Librerías externas)
    }
    
    total_penalty = 0
    for f in findings:
        total_penalty += weights.get(f.severity, 0)
    
    # Iniciamos en 100 y restamos penalizaciones
    final_score = max(0, 100 - total_penalty)
    
    scan.score = final_score
    scan.save()
    logger.info(f"Score final calculado para scan {scan_id}: {final_score}")