from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .serializers import UserSerializer
from .models import User
import jwt, datetime
from django.contrib.auth.models import Group

admin_group, _ = Group.objects.get_or_create(name='Admin')  
editor_group, _ = Group.objects.get_or_create(name='Editor')
viewer_group, _ = Group.objects.get_or_create(name='Viewer')
class RegisterView(APIView):
    def post(self, request):
        
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.views import APIView
import jwt
import datetime

class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            raise AuthenticationFailed('Email and password are required')

        user = User.objects.filter(email=email).first()
        admin_group.user_set.add(user)

        if user is None:
            raise AuthenticationFailed('User not found!')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')

        response = Response()
        response.set_cookie(key='jwt', value=token, httponly=True)

        response.data = {
            'jwt': token
        }
        return response



 





from rest_framework.exceptions import AuthenticationFailed
from jwt.exceptions import DecodeError  # Importez DecodeError pour capturer les erreurs de décodage JWT
import jwt

class UserView(APIView):

       def get(self, request):
        token = request.COOKIES.get('jwt')
          

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:

            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')
        except DecodeError:
            raise AuthenticationFailed('Invalid token!')

        user = User.objects.filter(id=payload['id']).first()
        if not user:
            raise AuthenticationFailed('User not found!')

        serializer = UserSerializer(user)
        if user.groups.filter(name='Admin').exists():
            print("admin")
            user_id = request.query_params.get('id')
            if user_id:
                user = User.objects.filter(id=user_id).first()
                if not user:
                    raise AuthenticationFailed('User not found!')


        return Response({'user': serializer.data, 'email': user.email})








class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'success'
        }
        return response
        


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
 
class GetUsernameByEmail(APIView):
    def post(self, request):
        email = request.data.get('email')
      
        if not email:
            raise NotFound('Email is required')
 
 
        try:
            # Recherche de l'utilisateur en utilisant l'e-mail converti en minuscules
            user = User.objects.get(email=email)
            print(user.name)
        except User.DoesNotExist:
            raise NotFound('User not found')

        # Retourner le nom d'utilisateur de l'utilisateur trouvé
        return Response({'username': user.name})





from .serializers import UserSerializer
from .models import User
from rest_framework.response import Response
from rest_framework.views import APIView

class ListUsers(APIView):
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)





from django.http import Http404
from rest_framework import status

class deleteUser(APIView):
 
    def delete(self, request, id=None):
        if id is None:
            return Response({"error": "Method DELETE requires an 'id' parameter."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(pk=id)
        except User.DoesNotExist:
            raise Http404
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
