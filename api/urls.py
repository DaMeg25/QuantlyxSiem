from rest_framework.routers import DefaultRouter

from .views import (
    CollectionRunViewSet,
    FindingViewSet,
    LifecycleEventViewSet,
    ManagedAccountViewSet,
    PamSystemViewSet,
)

router = DefaultRouter()
router.register("platforms", PamSystemViewSet)
router.register("accounts", ManagedAccountViewSet)
router.register("events", LifecycleEventViewSet)
router.register("findings", FindingViewSet)
router.register("runs", CollectionRunViewSet)

urlpatterns = router.urls
