from app import analysis
from app.models import Scan
from celery import shared_task, current_task
from celery.result import AsyncResult
from django.http import HttpResponse
import json, logging

logger = logging.getLogger('app')

@shared_task
def task_create_scan(scan_id):
    # 1. Iniciar estado
    current_task.update_state(state='STARTED', 
                              meta={'current': 1, 'total': 100, 'status': 'Analizando APK...'})
    
    # 2. Ejecutar el análisis (Androguard + Búsqueda de patrones)
    analysis.analyze_apk(current_task, scan_id)
    
    # 3. Calcular Score y Filtrar (Llamando a la función que movimos a analysis.py)
    analysis.calculate_final_score(scan_id)

    # 4. Finalizar
    current_task.update_state(state='SUCCESS', 
                              meta={'current': 100, 'total': 100, 'status': 'Finished'})

def scan_state(request, id):
    scan = Scan.objects.get(pk=id)
    job = AsyncResult(scan.task)
    data = {"status": "Unknown"}
    try:
        if (job.info):
            data = job.info
        else:
            data = job.result
    except Exception as e:
        logger.error(e)
    return HttpResponse(json.dumps(data), content_type='application/json')