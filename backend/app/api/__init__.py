from fastapi import APIRouter
from .routes import auth, devices, url, scan, threats, network, email, ai, quarantine, audit, reports, permissions, apk

router = APIRouter()
router.include_router(auth.router)
router.include_router(devices.router)
router.include_router(url.router)
router.include_router(scan.router)
router.include_router(threats.router)
router.include_router(network.router)
router.include_router(email.router)
router.include_router(ai.router)
router.include_router(quarantine.router)
router.include_router(audit.router)
router.include_router(reports.router)
router.include_router(permissions.router)
router.include_router(apk.router)
