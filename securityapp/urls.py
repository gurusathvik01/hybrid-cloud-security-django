from django.urls import path
from django.shortcuts import redirect
from . import views

urlpatterns = [
    # Redirect root (/) → login page
    path("", lambda request: redirect("login_selection"), name="home_redirect"),

    # Login selection page (user chooses Admin/User)
    path("login/", views.login_selection_view, name="login_selection"),

    # Separate login pages
    path("login/admin/", views.admin_login_view, name="admin_login"),
    path("login/user/", views.user_login_view, name="user_login"),

    # Signup (if needed)
    path("signup/", views.signup_view, name="signup"),

    # Dashboards
    path("dashboard/", views.dashboard_redirect, name="dashboard_redirect"),
    path("dashboard/admin/", views.admin_dashboard, name="admin_dashboard"),
    path("dashboard/user/", views.user_dashboard, name="user_dashboard"),

    # Index (manual access only)
    path("index/", views.user_page, name="user_page"),

    # PDF and AI routes
    path("admin/ai_solution/<int:event_id>/", views.ai_solution_view, name="ai_solution_view"),
    path("download_pdf/<int:event_id>/", views.download_prevention_pdf, name="download_pdf"),

    # Logout
    path("logout/", views.logout_view, name="logout"),



    path("file/<int:file_id>/", views.access_file, name="access_file"),


    path("files/", views.file_system_view, name="file_system"),
    path("files/<int:file_id>/access/", views.access_file, name="access_file"),


]
