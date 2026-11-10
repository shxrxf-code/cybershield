from fastapi import APIRouter
from app.api.v1 import urls, apks, documents, sms, emails, devices, network, reports

api_router = APIRouter()
api_router.include_router(urls.router)
api_router.include_router(apks.router)
api_router.include_router(documents.router)
api_router.include_router(sms.router)
api_router.include_router(emails.router)
api_router.include_router(devices.router)
api_router.include_router(network.router)
api_router.include_router(reports.router)
