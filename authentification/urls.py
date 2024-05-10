from django.urls import path
from .views import *

urlpatterns = [
    path('register', RegisterView.as_view()),
    path('login', LoginView.as_view()),
    path('user', UserView.as_view()),
    path('logout', LogoutView.as_view()),
    path('get-username-by-email', GetUsernameByEmail.as_view()), 
    path('users', ListUsers.as_view(), name='list_users'),
    path('deleteUser/<int:id>', deleteUser.as_view(), name='delete_user'),

]
