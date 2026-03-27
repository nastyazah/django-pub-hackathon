"""URL configuration for users app."""

from django.urls import include, path

from users.views import (
    SignDataView,
    DashboardView,
    DownloadPrivateKeyView,
    LoginStep1View,
    LogoutView,
    RegisterSuccessView,
    RegisterView,
)

urlpatterns = [
    path('', LoginStep1View.as_view()),
    path('register/', RegisterView.as_view(), name='register'),
    path('register/success/', RegisterSuccessView.as_view(), name='register-success'),
    path('register/private-key.pem', DownloadPrivateKeyView.as_view(), name='download-private-key'),
    path('login/', LoginStep1View.as_view(), name='login'),
    path('dashboard/', DashboardView.as_view(), name='dashboard'),
    path('sign/', SignDataView.as_view(), name='sign'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('ecp/', include('django_ecp_auth.urls')),
]
