from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include("ticektingOperationsApp.urls")),
    path('schemas/', SpectacularAPIView.as_view(), name = 'schema'),
    path('schemas/docs', SpectacularSwaggerView.as_view(url_name = "schema"))
]